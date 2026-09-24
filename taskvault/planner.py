"""Planner mode: provenance-tracked execution (CaMeL-style).

The value-matching checks in `Task.act` can be dodged by a hijacked model that
rewrites or encodes data. Planner mode closes that gap by never letting a model
that has seen untrusted data decide anything:

  1. A plan is written from the *trusted* request only (by a developer, a task
     template, or a privileged LLM that never sees tool output).
  2. The interpreter runs the plan. Every value carries labels saying where it
     came from (source, field, owner, secret/protected, trusted/untrusted).
  3. Untrusted text is only ever processed by a *quarantined* extractor
     (an LLM with no tools) whose output inherits the labels of its inputs.
     Rewording or base64-encoding data can't strip its labels.
  4. Before every action the interpreter checks the labels, not the strings:
     - a recipient must not be derived from untrusted content,
     - protected data may only reach its owner (or internal domains),
     - secrets only reach sinks allowed to receive them.

Plan format (JSON / YAML / Python dicts):

    [
      {"id": "cust",  "read": "crm.customer"},
      {"id": "tkt",   "read": "inbox.ticket"},
      {"id": "facts", "extract": {"from": ["tkt.body"],
                                  "instruction": "What refund amount is requested?",
                                  "schema": {"amount": "number"}}},
      {"id": "msg",   "format": "Hi {cust.name}, we've refunded ${facts.amount}."},
      {"act": "payments.refund", "args": {"card": "$cust.card_number", "amount": "$facts.amount"}},
      {"act": "email.send", "args": {"to": "$cust.email", "subject": "Refund", "body": "$msg"}}
    ]

References: `$var`, `$var.field`, `$trusted.name`; literals are plain values.

An action can be conditional: {"act": ..., "when": "$facts.wants_refund"}. A
condition derived from untrusted text lets that text decide *whether* a
pre-approved action happens (one bit), never *what* it does or where data goes.
Conditions are recorded in the audit log.
"""

from __future__ import annotations

import re
import string
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .vault import Blocked, Label, Task, owner_of

REF = re.compile(r"^\$(\w+)(?:\.(\w+))?$")
UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class Labeled:
    value: Any
    labels: frozenset[Label] = field(default_factory=frozenset)

    @property
    def untrusted(self) -> bool:
        return any(l.trust == UNTRUSTED for l in self.labels)


# A quarantined extractor: (instruction, inputs, schema) -> dict matching schema.
# It must have NO tool access. See taskvault.llm for real implementations.
Extractor = Callable[[str, dict[str, Any], dict[str, str]], dict[str, Any]]


class PlanError(ValueError):
    pass


class Planner:
    def __init__(self, task: Task, extractor: Extractor | None = None):
        self.task, self.extractor = task, extractor
        self.vars: dict[str, dict[str, Labeled] | Labeled] = {}
        self.results: list[Any] = []

    # ----------------------------------------------------------------- running
    def run(self, plan: Iterable[dict[str, Any]]) -> list[Any]:
        plan = list(plan)
        validate(plan)
        for step in plan:
            if "read" in step:
                self._read(step)
            elif "extract" in step:
                self._extract(step)
            elif "format" in step:
                self.vars[step["id"]] = self._format(step["format"])
            elif "act" in step:
                if "when" in step:
                    cond = self._resolve(step["when"])
                    self.task.vault.audit.record("condition", task=self.task.id, sink=step["act"],
                                                 value=bool(cond.value), untrusted=cond.untrusted)
                    if not cond.value:
                        continue
                self.results.append(self._act(step))
        return self.results

    def _read(self, step: dict[str, Any]) -> None:
        key = self._resolve(step["key"]).value if "key" in step else None
        record = self.task.read(step["read"], key)
        src = self.task.vault.policy.sources[step["read"]]
        key = key if key is not None else self.task.allowed_keys(step["read"])[0]
        owner = owner_of(src, key, self.task.vault._fetch(src.name, key) or {})
        self.vars[step["id"]] = {
            f: Labeled(v, frozenset({Label(src.level(key, f), owner, src.name, f, src.trust)}))
            for f, v in record.items()
        }

    def _extract(self, step: dict[str, Any]) -> None:
        spec = step["extract"]
        if self.extractor is None:
            raise PlanError("plan needs an extractor (quarantined LLM) for 'extract' steps")
        inputs = {ref: self._resolve("$" + ref if not ref.startswith("$") else ref) for ref in spec["from"]}
        labels = frozenset().union(*(v.labels for v in inputs.values()))
        out = self.extractor(spec["instruction"], {k: v.value for k, v in inputs.items()}, spec["schema"])
        missing = set(spec["schema"]) - set(out or {})
        if missing:
            raise PlanError(f"extractor did not return {sorted(missing)}")
        # Everything the extractor returns inherits every input label: it could encode any of it.
        # A missing answer (None) is kept as None: a "when" on it simply doesn't run the action.
        self.vars[step["id"]] = {k: Labeled(None if out[k] is None else _coerce(out[k], t), labels)
                                 for k, t in spec["schema"].items()}
        self.task.vault.audit.record("extract", task=self.task.id, step=step["id"],
                                     inputs=sorted(spec["from"]), decision="allow")

    def _format(self, template: str) -> Labeled:
        labels: set[Label] = set()
        values: dict[str, Any] = {}
        for _, name, _, _ in string.Formatter().parse(template):
            if name:
                lv = self._resolve("$" + name)
                labels |= lv.labels
                values[name] = lv.value
        text = template
        for name, v in values.items():
            text = text.replace("{" + name + "}", str(v))
        return Labeled(text, frozenset(labels))

    def _act(self, step: dict[str, Any]) -> Any:
        sink = step["act"]
        args = {k: self._resolve(v) for k, v in (step.get("args") or {}).items()}
        rule = self.task.template.sinks.get(sink)
        recipient_arg = rule.recipient_arg if rule else None

        reasons = []
        recipients: list[Any] = []
        if recipient_arg and recipient_arg in args:
            rv = args[recipient_arg]
            recipients = rv.value if isinstance(rv.value, list) else [rv.value]
            recipients = [self.task._unpseudo(r) for r in recipients]
            if rv.untrusted:
                reasons.append((f"recipient for {sink!r} was derived from untrusted content", None))
        for name, lv in args.items():
            for label in lv.labels:
                if label.level == "secret" and (not rule or label.field not in rule.secrets_allowed):
                    reasons.append((f"argument {name!r} carries secret {label.source}.{label.field}", None))
                if label.level in ("protected", "secret"):
                    for r in recipients:
                        if not self.task._owner_ok(label, r):
                            safe = (f"argument {name!r} carries {label.source}.{label.field} "
                                    "to a recipient who isn't its owner")
                            reasons.append((safe, safe.replace(" to a", f" (owner {label.owner}) to a")))
        for reason, shown in dict.fromkeys(reasons):
            self.task._decide("act", "provenance: " + reason, shown=shown and "provenance: " + shown, sink=sink)
        # Then the ordinary checks (trusted recipients, value matching, approvals) and execution.
        return self.task.act(sink, **{k: v.value for k, v in args.items()})

    # --------------------------------------------------------------- helpers
    def _resolve(self, ref: Any) -> Labeled:
        if isinstance(ref, str):
            m = REF.match(ref)
            if m:
                name, attr = m.groups()
                if name == "trusted":
                    if attr not in self.task.trusted:
                        raise PlanError(f"unknown trusted input {attr!r}")
                    return Labeled(self.task.trusted[attr])
                if name not in self.vars:
                    raise PlanError(f"unknown variable ${name}")
                var = self.vars[name]
                if isinstance(var, Labeled):
                    if attr:
                        raise PlanError(f"${name} has no field {attr!r}")
                    return var
                if attr is None:
                    labels = frozenset().union(*(v.labels for v in var.values()))
                    return Labeled({k: v.value for k, v in var.items()}, labels)
                if attr not in var:
                    raise PlanError(f"${name} has no field {attr!r}")
                return var[attr]
        if isinstance(ref, list):
            items = [self._resolve(r) for r in ref]
            labels = frozenset().union(*(i.labels for i in items)) if items else frozenset()
            return Labeled([i.value for i in items], labels)
        return Labeled(ref)   # literal written in the (trusted) plan


def validate(plan: list[dict[str, Any]]) -> None:
    """Static checks: known step kinds, ids defined before use, no duplicate ids."""
    defined: set[str] = {"trusted"}
    kinds = ("read", "extract", "format", "act")
    for i, step in enumerate(plan):
        kind = [k for k in kinds if k in step]
        if len(kind) != 1:
            raise PlanError(f"step {i}: needs exactly one of {kinds}")
        if kind[0] != "act":
            sid = step.get("id")
            if not sid or not re.fullmatch(r"\w+", sid) or sid in defined:
                raise PlanError(f"step {i}: needs a new, simple 'id'")
        for ref in _refs(step):
            if ref not in defined:
                raise PlanError(f"step {i}: uses ${ref} before it is defined")
        if kind[0] != "act":
            defined.add(step["id"])


def _refs(step: dict[str, Any]) -> set[str]:
    found: set[str] = set()

    def walk(v: Any) -> None:
        if isinstance(v, str):
            m = REF.match(v)
            if m:
                found.add(m.group(1))
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)

    if "format" in step:
        for _, name, _, _ in string.Formatter().parse(step["format"]):
            if name:
                found.add(name.split(".")[0])
    if "extract" in step:
        found |= {r.lstrip("$").split(".")[0] for r in step["extract"].get("from", [])}
    walk(step.get("args"))
    walk(step.get("key"))
    walk(step.get("when"))
    return found


def _coerce(v: Any, t: str) -> Any:
    try:
        if t == "number":
            return float(v)
        if t == "integer":
            return int(v)
        if t == "boolean":
            return v if isinstance(v, bool) else str(v).lower() in ("true", "yes", "1")
    except (TypeError, ValueError) as e:
        raise PlanError(f"extractor returned {v!r}, expected {t}") from e
    return str(v)


__all__ = ["Blocked", "Labeled", "PlanError", "Planner", "validate"]
