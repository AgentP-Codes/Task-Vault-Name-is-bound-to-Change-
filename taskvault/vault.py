"""The vault: task-scoped reads, placeholders for secrets, owner-bound outbound checks.

The agent never talks to source systems. It asks the vault for data inside a
Task, and every outbound action goes back through the same Task:

    vault = Vault(policy, sources={...}, sinks={...})
    task = vault.start_task("support_reply", customer_id=12)   # trusted input only
    customer = task.read("crm.customer")                          # scoped to customer 12
    task.act("email.send", to=customer["email"], body="...")     # checked before it runs

Guarantees enforced here (see docs/threat-model.md):
  1. A task can only read records and fields its template allows, keyed from
     trusted inputs - never from what the model asks for.
  2. Secret fields never reach the model: they are swapped for placeholders and
     only turned back into real values for sinks allowed to receive them.
  3. Protected values only flow to their owner (customer 12's data only to
     customer 12's verified address) or, for company data, internal domains.
  4. Recipients must come from trusted data, never from untrusted content.
  5. Every read and action is recorded in a hash-chained audit log.

Guarantee 3 is enforced here by matching values in outbound arguments. For
guarantees that survive rewording and encoding, use `taskvault.planner`, which
tracks labels through the data flow instead of matching strings.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import itertools
import json
import logging
import os
import re
import secrets
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .boxes import BoxLocked, is_box_ref
from .cache import EncryptedCache
from .crypto import Cipher
from .errors import TaskvaultError
from .policy import Policy, SinkRule, TaskTemplate
from .store import SecretStore, is_ref

log = logging.getLogger("taskvault")

TOKEN_RE = re.compile(r"\[\[vault:([a-z0-9_]+):([a-f0-9]{8})\]\]")
LOOSE_TOKEN_RE = re.compile(r"\[\[\s*vault\s*:[^\]]*\]\]?", re.I)   # anything that looks like a placeholder
MIN_MATCH_LEN = 4  # shorter values produce too many false matches
_NO_RULE = SinkRule()


class Blocked(TaskvaultError):
    """Raised when the vault refuses a read or an action. `reason` is safe to show the model."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class SinkError(TaskvaultError):
    """A sink (your own code) raised an error. The message has real values masked, as the model may see it."""


@dataclass(frozen=True)
class Label:
    level: str          # secret | protected | normal
    owner: str          # "company" or e.g. "customer_id:12"
    source: str
    field: str
    trust: str = "trusted"


@dataclass
class ApprovalRequest:
    task_id: int
    template: str
    sink: str
    reason: str
    args: dict[str, Any]   # as the agent sent them: placeholders, not real secrets


Approver = Callable[[ApprovalRequest], bool]


@dataclass
class FlagEvent:
    """An allowed action worth a human look (medium risk, or unusual for this task)."""
    task_id: int
    template: str
    sink: str
    reasons: list[str]


class Vault:
    def __init__(self, policy: Policy,
                 sources: dict[str, Callable[[Any], dict | None]],
                 sinks: dict[str, Callable[..., Any]],
                 audit: AuditLog | None = None,
                 mode: str = "enforce",
                 cipher: Cipher | None = None,
                 cache: EncryptedCache | None = None,
                 approver: Approver | None = None,
                 recorder: Any = None,
                 store: SecretStore | None = None,
                 boxes: Any = None,
                 baseline: Any = None,
                 on_flag: Callable[[FlagEvent], None] | None = None):
        if mode not in ("enforce", "shadow"):
            raise ValueError("mode must be 'enforce' or 'shadow'")
        for name in policy.sources:
            if name not in sources:
                raise ValueError(f"policy source {name!r} has no connector")
        self.policy, self.sources, self.sinks = policy, sources, sinks
        self.audit = audit if audit is not None else AuditLog()
        self.mode, self.cipher, self.cache = mode, cipher, cache
        self.approver, self.recorder = approver, recorder
        self.store, self.baseline, self.on_flag = store, baseline, on_flag
        self.boxes = boxes
        self._fp_key = os.urandom(32)
        self._task_ids = itertools.count(1)

    # ---------------------------------------------------------------- helpers
    def fp(self, value: Any) -> str:
        """Keyed fingerprint so logs can correlate values without storing them."""
        if self.cipher:
            return self.cipher.fingerprint(value)
        return hmac.new(self._fp_key, str(value).encode(), hashlib.sha256).hexdigest()[:16]

    def pseudonym(self, value: Any, source: str, field: str) -> str:
        """A stable, readable stand-in for a real value. Same input -> same pseudonym."""
        pid = self.fp(f"pseudo\x00{source}\x00{field}\x00{value}")[:6]
        text = str(value)
        if "@" in text and " " not in text.strip():
            return f"{field.replace('_', '-')}-{pid}@pseudonym.invalid"
        return f"{field.replace('_', ' ').title().replace(' ', '')}-{pid.upper()}"

    def start_task(self, template: str, **trusted: Any) -> Task:
        if template not in self.policy.tasks:
            raise KeyError(f"no task template {template!r}")
        t = self.policy.tasks[template]
        missing = [k for k in t.trusted if trusted.get(k) in (None, "")]
        if missing:
            raise ValueError(f"task {template!r} needs trusted inputs: {missing}")
        task = Task(self, t, next(self._task_ids), trusted)
        self.audit.record("task.start", task=task.id, template=template,
                          trusted={k: self.fp(v) for k, v in trusted.items()})
        if self.recorder:
            self.recorder.task_started(template, trusted)
        return task

    def _fetch(self, source: str, key: Any) -> dict | None:
        """Read-through: short-lived encrypted cache first, then the source system."""
        if self.cache is not None:
            hit = self.cache.get(source, key)
            if hit is not None:
                return hit
        record = self.sources[source](key)
        if self.recorder:
            self.recorder.source_read(source, key, record)
        if record is not None and self.cache is not None:
            self.cache.put(source, key, record)
        return record

    def _owner_contact(self, owner: str) -> str | None:
        """The verified destination for a data owner, e.g. customer 12's email on file."""
        if owner == "company" or ":" not in owner:
            return None
        key_name, key = owner.split(":", 1)
        for src in self.policy.sources.values():
            if src.owner == key_name and src.owner_contact and src.trust == "trusted":
                rec = self._fetch(src.name, _coerce(key))
                if rec and rec.get(src.owner_contact):
                    return rec[src.owner_contact]
        return None


class Task:
    def __init__(self, vault: Vault, template: TaskTemplate, task_id: int, trusted: dict[str, Any]):
        self.vault, self.template, self.id, self.trusted = vault, template, task_id, trusted
        self._tokens: dict[str, tuple[Any, Label]] = {}   # placeholder -> (sealed value, label)
        self._seen: dict[str, Label] = {}                   # protected/secret value -> label
        self._calls: dict[str, int] = {}
        self._reported: set[str] = set()
        self._pseudo: dict[str, Any] = {}                   # pseudonym -> real value

    # ------------------------------------------------------------------ reads
    def read(self, source: str, key: Any = None) -> dict[str, Any]:
        """Return one record, filtered to allowed fields, with secrets as placeholders."""
        self._reported = set()
        if source not in self.vault.policy.sources:
            self._decide("read", "unknown source", shown=f"unknown source {source!r}",
                         source=self.vault.fp(source))
            raise KeyError(f"unknown source {source!r}")
        rule = self.template.reads.get(source)
        allowed_keys = self.allowed_keys(source)
        if key is None and len(allowed_keys) == 1:
            key = allowed_keys[0]
        if rule is None or str(key) not in {str(k) for k in allowed_keys}:
            self._decide("read", f"{source} record is outside this task's scope",
                         shown=f"{source}:{key} is outside this task's scope",
                         source=source, key=self.vault.fp(key))
            rule = {"fields": None}   # shadow mode only: observe what an unscoped read returns
        record = self.vault._fetch(source, key)
        if record is None:
            raise KeyError(f"{source}:{key} not found")
        src = self.vault.policy.sources[source]
        owner = owner_of(src, key, record)
        fields = rule.get("fields") or list(record)
        out: dict[str, Any] = {}
        for f in fields:
            if f not in record:
                continue
            label = Label(src.level(key, f, record), owner, source, f, src.trust)
            value = record[f]
            if label.level == "secret" or is_box_ref(value):
                # high-tier box items stay locked: only a reference is sealed, opened at the sink
                if is_ref(value) and self.vault.store is not None:
                    value = self.vault.store.get(value)       # long-term secret kept in the vault
                out[f] = self._seal(value, label)
            else:
                if label.level == "protected":
                    self._remember(value, label)
                if f in src.pseudonymize and value not in (None, ""):
                    p = self.vault.pseudonym(value, source, f)
                    self._pseudo[p] = value
                    value = p
                out[f] = value
        self.vault.audit.record("read", task=self.id, source=source, key=self.vault.fp(key),
                                fields=sorted(out), decision="allow")
        return out

    def allowed_keys(self, source: str) -> list[Any]:
        rule = self.template.reads.get(source) or {}
        keys = rule.get("keys", [rule["key"]] if "key" in rule else [])
        out = []
        for k in keys:
            m = re.fullmatch(r"\{(\w+)\}", k) if isinstance(k, str) else None
            out.append(self.trusted[m.group(1)] if m else (k.format(**self.trusted) if isinstance(k, str) else k))
        return out

    def _seal(self, value: Any, label: Label) -> str:
        token = f"[[vault:{label.field}:{secrets.token_hex(4)}]]"
        sealed = self.vault.cipher.encrypt(value, aad=token) if self.vault.cipher else value
        self._tokens[token] = (sealed, label)
        self._seen[str(value)] = label
        return token

    def _unseal(self, token: str) -> Any:
        sealed, _ = self._tokens[token]
        value = self.vault.cipher.decrypt(sealed, aad=token) if self.vault.cipher else sealed
        if is_box_ref(value):
            if self.vault.boxes is None:
                raise BoxLocked("this value is in a deposit box but no box store is configured")
            # second key: the holder's (may ask a person to approve)
            value = self.vault.boxes.reveal(value, task=self.id, reason=f"{self.template.name} -> "
                                                                         f"{getattr(self, '_sink', '?')}")
        return value

    def _remember(self, value: Any, label: Label) -> None:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = str(value)
        if isinstance(value, str):
            for piece in [value, *[l.strip() for l in value.splitlines()]]:
                if len(piece) >= MIN_MATCH_LEN:
                    self._seen[piece] = label
        elif isinstance(value, (list, dict)):
            for v in (value.values() if isinstance(value, dict) else value):
                self._remember(v, label)

    # ---------------------------------------------------------------- actions
    def act(self, sink: str, **args: Any) -> Any:
        """Check an outbound action, swap placeholders back to real values, then run it."""
        self._reported = set()
        shown = args                                        # what the agent sent (for approvals and replay)
        args = {k: self._unpseudo(v) for k, v in args.items()}   # checks run on real values
        if sink not in self.vault.sinks:
            self._decide("act", "unknown sink", shown=f"unknown sink {sink!r}", sink=self.vault.fp(sink))
            raise KeyError(f"unknown sink {sink!r}")   # shadow mode: nothing to run
        rule = self.template.sinks.get(sink)
        if rule is None:
            self._decide("act", f"sink {sink!r} is not allowed for this task", sink=sink)
            rule = _NO_RULE

        if rule.args is not None and (extra := sorted(set(args) - set(rule.args))):
            self._decide("act", f"{sink!r} does not accept some of the arguments given",
                         shown=f"{sink!r} does not accept arguments {extra}", sink=sink)

        n = self._calls.get(sink, 0) + 1
        if rule.max_calls is not None and n > rule.max_calls:
            self._decide("act", f"{sink!r} called more than {rule.max_calls} times in one task", sink=sink)

        recipient_args = [rule.recipient_arg] if rule.recipient_arg else []
        if rule.recipient_arg:     # cc, bcc, reply_to... get the same checks as the main recipient
            recipient_args += [a for a in args if a != rule.recipient_arg and a.lower() in _RECIPIENT_ARGS]
        recipients = [r for a in recipient_args for r in _as_list(args.get(a))]
        if rule.recipient_arg:
            trusted = self._trusted_recipients(rule.allowed_recipients)
            for r in recipients or [None]:
                if not _matches(r, trusted):
                    self._decide("act", "recipient did not come from trusted data",
                                 shown=f"recipient {r!r} did not come from trusted data",
                                 sink=sink, recipient=self.vault.fp(r))

        text = _flatten(args)

        # Something that looks like a placeholder but isn't a valid one: damaged or forged.
        if any(not TOKEN_RE.fullmatch(m.group(0)) for m in LOOSE_TOKEN_RE.finditer(text)):
            self._decide("act", "damaged or forged placeholder", sink=sink)

        # Placeholders: only sinks allowed to receive that secret, and only for its owner.
        for token in sorted(set(m.group(0) for m in TOKEN_RE.finditer(text))):
            field = TOKEN_RE.fullmatch(token).group(1)
            if token not in self._tokens:
                self._decide("act", "unknown or foreign placeholder", sink=sink)
                continue
            if field not in rule.secrets_allowed:
                self._decide("act", f"secret field {field!r} may not be sent to {sink!r}", sink=sink)
            elif isinstance(rule.secrets_allowed, dict):
                want = rule.secrets_allowed[field]
                where = [k for k, v in args.items() if token in _flatten({k: v})]
                if where != [want] or args.get(want) != token:
                    self._decide("act", f"secret field {field!r} may only be passed as {want!r} to {sink!r}",
                                 sink=sink)
            for r in recipients:
                if not self._owner_ok(self._tokens[token][1], r):
                    self._decide("act", "secret would go to someone other than its owner", sink=sink)

        # Raw protected/secret values: only to their owner (or internal domains for company data).
        lowered = text.lower()
        for value, label in self._seen.items():
            if value.lower() not in lowered:
                continue
            if label.level == "secret":
                self._decide("act", f"raw secret {label.field!r} in outbound action", sink=sink)
            for r in recipients:
                if not self._owner_ok(label, r):
                    self._decide("act", f"{label.source}.{label.field} may not be sent to anyone but its owner",
                                 shown=f"{label.source}.{label.field} (owner {label.owner}) "
                                       f"may not be sent to this recipient", sink=sink,
                                 recipient=self.vault.fp(r))

        if self.vault.policy.detect_outbound and recipients:
            from .detect import KINDS, scan_text
            for kind, _s, _e in scan_text(TOKEN_RE.sub(" ", text)):
                if KINDS[kind].level == "secret":
                    self._decide("act", f"outbound message contains what looks like a {KINDS[kind].label}",
                                 sink=sink)

        if rule.approval == "always":
            self._approve(sink, "policy requires a human to approve this action", shown)

        classes = [self._recipient_class(r, rule) for r in recipients]
        sizes = {k: len(str(v)) for k, v in args.items()}
        flags = []
        if rule.risk == "medium":
            flags.append("medium-risk action")
        if self.vault.baseline is not None:
            flags += self.vault.baseline.check(self.template.name, sink, n, sorted(args), classes, sizes)

        self._calls[sink] = n
        self._sink = sink
        if self.vault.mode == "enforce":
            for a in recipient_args:     # the sink gets the checked address, not the text the agent wrote
                v = args.get(a)
                if isinstance(v, str) and v.strip():
                    args[a] = ", ".join(_norm(x) for x in _as_list(v))
                elif isinstance(v, (list, tuple)):
                    args[a] = [_norm(x) for x in v]
        try:
            resolved = {k: self._resolve(v) for k, v in args.items()}
        except BoxLocked as e:
            self.vault.audit.record("act", task=self.id, sink=sink, decision="block", reason=f"box locked: {e}")
            raise Blocked(f"box locked: {e}") from e
        except Exception as e:  # noqa: BLE001 - damaged or missing stored secret: fail closed, and log it
            self.vault.audit.record("act", task=self.id, sink=sink, decision="block",
                                    reason=f"a stored secret couldn't be unlocked ({type(e).__name__})")
            raise Blocked("a stored secret couldn't be unlocked; the action was not run") from None
        self.vault.audit.record("act", task=self.id, sink=sink, args=[self._safe_name(a) for a in sorted(args)],
                                recipients=[self.vault.fp(r) for r in recipients], recipient_classes=classes,
                                arg_sizes={self._safe_name(k): v for k, v in sizes.items()}, call=n,
                                decision="allow")
        if flags:
            self._flag(sink, flags)
        mask = self._mask_map(args, resolved)
        try:
            result = self.vault.sinks[sink](**resolved)
        except Exception as e:  # noqa: BLE001 - the error text may quote real values; mask them
            raise SinkError(f"{sink} failed: {type(e).__name__}: {_mask(str(e), mask)}") from None
        result = _mask(result, mask)
        if self.vault.recorder:
            self.vault.recorder.sink_called(sink, shown, result)
        if self.vault.cache is not None:
            for src in rule.invalidates:
                self.vault.cache.invalidate_source(src)
        return result

    # ------------------------------------------------------------- tool layer
    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Dispatch an agent-facing tool name using the policy's `tools` map."""
        arguments = dict(arguments or {})
        tm = self.vault.policy.tools.get(name)
        if tm is None:
            self._decide("act", "tool is not exposed", shown=f"tool {name!r} is not exposed",
                         tool=self.vault.fp(name))
            raise Blocked(f"tool {name!r} is not exposed")
        for arg, kind in (tm.params or {}).items():     # the declared JSON types, checked before anything runs
            if arg in arguments and not _json_type_ok(arguments[arg], kind):
                self._decide("act", f"tool argument has the wrong type (expected {kind})",
                             shown=f"argument {arg!r} of {name!r} must be a {kind}", tool=name)
        if tm.read:
            key = arguments.get(tm.key_arg) if tm.key_arg else None
            return self.read(tm.read, key)
        return self.act(tm.act, **arguments)

    def tool_specs(self) -> list[dict[str, Any]]:
        """Tool definitions (name, description, JSON schema) for this task, for LLM adapters."""
        specs = []
        for tm in self.vault.policy.tools.values():
            if tm.read and tm.read not in self.template.reads:
                continue
            if tm.act and tm.act not in self.template.sinks:
                continue
            props: dict[str, Any] = {k: {"type": v} for k, v in tm.params.items()}
            required = list(tm.params)
            if tm.read and tm.key_arg and tm.key_arg not in props:
                props[tm.key_arg] = {"type": "string", "description": "record id (optional)"}
            specs.append({"name": tm.name, "description": tm.description or (tm.read or tm.act),
                          "input_schema": {"type": "object", "properties": props, "required": required}})
        return specs

    # ---------------------------------------------------------------- checks
    def _trusted_recipients(self, specs: list[str]) -> list[str]:
        out = []
        for spec in specs:
            spec = spec.format(**self.trusted)
            m = re.fullmatch(r"([\w.]+):([^.]+)\.(\w+)", spec)
            if m and m.group(1) in self.vault.policy.sources:
                # e.g. crm.customer:12.email -> looked up by the vault itself, not by the model
                src = self.vault.policy.sources[m.group(1)]
                if src.trust != "trusted":
                    continue
                rec = self.vault._fetch(m.group(1), _coerce(m.group(2)))
                if rec and rec.get(m.group(3)):
                    out.extend(_norm(v) for v in _as_list(rec[m.group(3)]))
            else:
                out.append(_norm_pattern(spec))   # literal address or glob like *@acme.example
        return out

    def _owner_ok(self, label: Label, recipient: Any) -> bool:
        """Protected data may go to its owner, or to the company's own domains (it already holds it)."""
        r = _norm(recipient)
        if r in ("", _INVALID):
            return False
        if "@" in r and r.rsplit("@", 1)[-1] in self.vault.policy.internal_domains:
            return True
        if label.owner == "company":
            return False
        contact = self.vault._owner_contact(label.owner)
        return contact is not None and _norm(contact) == r

    def _approve(self, sink: str, reason: str, args: dict[str, Any]) -> None:
        req = ApprovalRequest(self.id, self.template.name, sink, reason, dict(args))
        ok = bool(self.vault.approver and self.vault.approver(req))
        self.vault.audit.record("approval", task=self.id, sink=sink, reason=reason,
                                decision="approved" if ok else "denied")
        if not ok:
            raise Blocked(f"{reason}: {'denied' if self.vault.approver else 'no approver configured'}")

    def _resolve(self, value: Any) -> Any:
        if isinstance(value, str):
            return TOKEN_RE.sub(lambda m: str(self._unseal(m.group(0))) if m.group(0) in self._tokens
                                else m.group(0), value)
        if isinstance(value, list):
            return [self._resolve(v) for v in value]
        if isinstance(value, dict):
            return {k: self._resolve(v) for k, v in value.items()}
        return value

    def _unpseudo(self, value: Any) -> Any:
        """Swap pseudonyms back to real values (the agent only ever saw the pseudonyms)."""
        if not self._pseudo:
            return value
        if isinstance(value, str):
            for p, real in self._pseudo.items():
                if p in value:
                    value = value.replace(p, str(real))
            return value
        if isinstance(value, list):
            return [self._unpseudo(v) for v in value]
        if isinstance(value, dict):
            return {k: self._unpseudo(v) for k, v in value.items()}
        return value

    def _safe_name(self, name: str) -> str:
        """Argument names chosen by the agent: kept if they look like names, else fingerprinted."""
        return name if _NAME_RE.fullmatch(str(name)) else "fp:" + self.vault.fp(name)

    def _mask_map(self, shown: dict[str, Any], resolved: dict[str, Any]) -> dict[str, str]:
        """Real value -> what the agent saw (placeholder or pseudonym), for masking sink output."""
        out: dict[str, str] = {}
        for token in set(m.group(0) for m in TOKEN_RE.finditer(_flatten(shown))):
            if token in self._tokens:
                real = str(self._resolve(token))
                if real and real != token:
                    out[real] = token
        for pseudo, real in self._pseudo.items():
            if str(real):
                out.setdefault(str(real), pseudo)
        return out

    def _recipient_class(self, recipient: Any, rule: SinkRule) -> str:
        r = _norm(recipient)
        if "@" in r and r.rsplit("@", 1)[-1] in self.vault.policy.internal_domains:
            return "internal"
        for spec in rule.allowed_recipients:
            if re.fullmatch(r"([\w.]+):([^.]+)\.(\w+)", spec.format(**self.trusted)) and \
                    r in self._trusted_recipients([spec]):
                return "owner"
        return "listed"

    def _flag(self, sink: str, reasons: list[str]) -> None:
        self.vault.audit.record("flag", task=self.id, sink=sink, reasons=reasons, decision="flag")
        if self.vault.on_flag:
            self.vault.on_flag(FlagEvent(self.id, self.template.name, sink, reasons))

    def _decide(self, kind: str, reason: str, shown: str | None = None, **fields: Any) -> None:
        """Block (or, in shadow mode, record) an action.

        `reason` goes to the log and the audit file, so it must never contain data values
        (addresses, record keys, owners): only names from the policy. `shown` is the fuller
        message for the caller, who supplied those values in the first place.
        """
        log.info("%s %s: %s", "would block" if self.vault.mode == "shadow" else "blocked", kind, reason)
        if self.vault.mode == "shadow":
            if (shown or reason) not in self._reported:
                self._reported.add(shown or reason)
                self.vault.audit.record(kind, task=self.id, decision="would_block", reason=reason, **fields)
            return
        self.vault.audit.record(kind, task=self.id, decision="block", reason=reason, **fields)
        raise Blocked(shown or reason)


def owner_of(src: Any, key: Any, record: dict) -> str:
    """'company', or '<owner>:<id>' where id is the record key or its owner_field."""
    if src.owner == "company":
        return "company"
    oid = record.get(src.owner_field) if src.owner_field else key
    return f"{src.owner}:{oid}"


_INVALID = "\x00invalid"
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_RECIPIENT_ARGS = {"to", "cc", "bcc", "reply_to", "replyto", "reply-to", "recipient", "recipients"}

_ATOM = r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_EMAIL_RE = re.compile(rf"{_ATOM}(?:\.{_ATOM})*@{_LABEL}(?:\.{_LABEL})+")
_PLAIN_ID_RE = re.compile(r"[a-z0-9+][a-z0-9+._:/-]*")          # phone numbers, account ids, URLs' paths...
_DISPLAY_RE = re.compile(r"([^<>@\"\\]*)<([^<>]+)>")


def _norm(v: Any) -> str:
    """Canonical form for comparing recipients.

    Accepts exactly one plain address ("a@b.com", any case, surrounding spaces) or
    "Display Name <a@b.com>" with no '@' in the name; or, for non-email recipients, one plain
    identifier. Anything else (a second address, comments, quoted parts, stray dots, control or
    invisible characters, look-alike letters, non-text values) normalises to a value that never
    matches a trusted recipient, so it's blocked rather than guessed.
    """
    if v is None:
        return ""
    if not isinstance(v, str):
        return _INVALID
    if any(c in v for c in "\r\n\t\x00") or any(unicodedata.category(c) in ("Cf", "Cc") for c in v):
        return _INVALID                      # header injection or invisible characters
    if unicodedata.normalize("NFKC", v) != v or not v.isascii():
        return _INVALID                      # look-alike characters
    s = v.strip()
    if "<" in s or ">" in s:
        m = _DISPLAY_RE.fullmatch(s)
        if not m:
            return _INVALID
        s = m.group(2).strip()
    s = s.lower()
    if "@" in s:
        return s if _EMAIL_RE.fullmatch(s) else _INVALID
    return s if _PLAIN_ID_RE.fullmatch(s) else _INVALID


def _json_type_ok(value: Any, kind: str) -> bool:
    checks = {"string": lambda v: isinstance(v, str),
              "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
              "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
              "boolean": lambda v: isinstance(v, bool),
              "array": lambda v: isinstance(v, list), "object": lambda v: isinstance(v, dict)}
    return checks.get(kind, lambda v: True)(value)


def _mask(value: Any, mask: dict[str, str]) -> Any:
    """Replace real values with what the agent saw, anywhere in a sink's result."""
    if not mask:
        return value
    if isinstance(value, str):
        for real in sorted(mask, key=len, reverse=True):
            if len(real) >= 3 and real in value:
                value = value.replace(real, mask[real])
        return value
    if isinstance(value, (list, tuple)):
        return type(value)(_mask(v, mask) for v in value)
    if isinstance(value, dict):
        return {k: _mask(v, mask) for k, v in value.items()}
    return value


def _norm_pattern(spec: str) -> str:
    """Allowed-recipient patterns from the policy (trusted): just trimmed and lower-cased."""
    return spec.strip().lower()


def _matches(recipient: Any, allowed: list[str]) -> bool:
    r = _norm(recipient)
    return bool(r) and r != _INVALID and any(r == a or (any(c in a for c in "*?[") and fnmatch.fnmatchcase(r, a))
                           for a in allowed)


def _as_list(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    if isinstance(v, str) and ("," in v or ";" in v):
        return [p.strip() for p in re.split(r"[,;]", v) if p.strip()]
    return [v]


def _flatten(args: dict[str, Any]) -> str:
    try:
        return json.dumps(args, default=str, ensure_ascii=False) + " " + " ".join(
            str(v) for v in args.values())
    except (TypeError, ValueError):
        return " ".join(str(v) for v in args.values())


def _coerce(key: Any) -> Any:
    return int(key) if isinstance(key, str) and key.isdigit() else key
