"""Policy file loading and validation.

A policy is plain YAML, kept in the developer's repo and reviewed like code:

  sources   what data the vault may pull, each field's label (secret |
            protected | normal) and who owns each record
  tasks     task templates: which records and fields a task may read (keyed
            only from trusted inputs) and which sinks it may use
  tools     how agent-facing tool names map to vault reads and actions
            (used by the MCP proxy and the LLM adapters)
  internal_domains   where company-owned protected data may be sent

See docs/policy-reference.md for every option.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import TaskvaultError

LEVELS = ("secret", "protected", "normal")
TRUST = ("trusted", "untrusted")


class PolicyError(TaskvaultError, ValueError):
    """The policy file is invalid. The message says where."""


@dataclass
class Source:
    name: str
    owner: str = "company"              # a trusted-input name (e.g. customer_id) or "company"
    owner_contact: str | None = None    # field holding the owner's verified destination
    owner_field: str | None = None      # record field holding the owner's id (default: the record key)
    fields: dict[str, str] = field(default_factory=dict)       # field -> level
    key_levels: dict[str, str] = field(default_factory=dict)   # record key -> level (documents)
    default_level: str = "protected"    # anything unlabelled is treated as protected
    trust: str = "trusted"              # "untrusted" for inboxes, web pages, tickets
    label_field: str | None = None      # field holding an existing label (e.g. a Purview sensitivity label)
    label_map: dict[str, str] = field(default_factory=dict)    # that label -> level
    pseudonymize: list[str] = field(default_factory=list)      # fields the model sees as stand-ins
    storage: str = "external"           # "external" (your systems) or "boxes" (taskvault deposit boxes)

    def level(self, key: Any, fieldname: str, record: dict | None = None) -> str:
        """Per-document label (label_map) beats per-key and per-field levels; the most sensitive wins."""
        levels = [self.key_levels.get(str(key)) or self.fields.get(fieldname, self.default_level)]
        if record is not None and self.label_field and fieldname != self.label_field:
            label = record.get(self.label_field)
            if label is not None:
                levels.append(self.label_map.get(str(label), self.default_level))
        return max(levels, key=LEVELS[::-1].index)


@dataclass
class SinkRule:
    recipient_arg: str | None = None
    allowed_recipients: list[str] = field(default_factory=list)   # specs or globs, see docs
    secrets_allowed: list[str] | dict[str, str] = field(default_factory=list)   # fields, or {field: arg}
    approval: str = "never"             # "never" | "always"
    max_calls: int | None = None        # per task
    invalidates: list[str] = field(default_factory=list)          # sources to drop from cache
    args: list[str] | None = None       # if set, the only argument names this sink accepts
    risk: str = "low"                   # low: allow | medium: allow + flag for review | high: human approval


@dataclass
class ToolMap:
    name: str
    read: str | None = None             # source name
    key_arg: str | None = None          # tool argument holding the record key
    act: str | None = None              # sink name
    description: str = ""
    params: dict[str, str] = field(default_factory=dict)   # arg -> JSON type, shown to the model


@dataclass
class TaskTemplate:
    name: str
    trusted: list[str]
    reads: dict[str, dict[str, Any]]
    sinks: dict[str, SinkRule]
    description: str = ""


@dataclass
class Policy:
    sources: dict[str, Source]
    tasks: dict[str, TaskTemplate]
    tools: dict[str, ToolMap] = field(default_factory=dict)
    internal_domains: list[str] = field(default_factory=list)
    cache_ttl_seconds: float = 300
    detect_outbound: bool = False       # also block outbound values that look like secrets (cards, TFNs, keys)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        try:
            raw = yaml.safe_load(Path(path).read_text()) or {}
        except yaml.YAMLError as e:
            raise PolicyError(f"{path}: invalid YAML: {e}") from e
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Policy:
        """Build a policy, rejecting anything of the wrong shape with a PolicyError that says where."""
        try:
            return cls._from_dict(raw)
        except PolicyError:
            raise
        except (AttributeError, TypeError, ValueError, KeyError) as e:
            raise PolicyError(f"the policy has a value of the wrong type or shape ({type(e).__name__}: {e})") from e

    @classmethod
    def _from_dict(cls, raw: dict[str, Any]) -> Policy:
        if not isinstance(raw, dict):
            raise PolicyError("a policy must be a mapping (key: value), not a list or a single value")
        for section in ("sources", "tasks", "tools", "upstream"):
            _mapping(raw.get(section), section, entries=section != "upstream")
        _str_list(raw.get("internal_domains"), "internal_domains")
        known = {"sources", "tasks", "tools", "internal_domains", "cache_ttl_seconds", "version", "upstream",
                 "detect_outbound"}
        if extra := set(raw) - known:
            raise PolicyError(f"unknown top-level keys: {sorted(extra)}")

        sources: dict[str, Source] = {}
        for name, s in (raw.get("sources") or {}).items():
            s = s or {}
            _str_list(s.get("pseudonymize"), f"source {name}: pseudonymize")
            _mapping(s.get("fields"), f"source {name}: fields")
            _mapping(s.get("key_levels"), f"source {name}: key_levels")
            _mapping(s.get("label_map"), f"source {name}: label_map")
            _only(s, {"owner", "owner_contact", "owner_field", "fields", "key_levels",
                          "default_level", "trust", "label_field", "label_map", "pseudonymize", "storage"},
                  f"source {name}")
            src = Source(name=name, owner=s.get("owner", "company"), owner_contact=s.get("owner_contact"),
                         owner_field=s.get("owner_field"), fields=s.get("fields") or {},
                         key_levels=s.get("key_levels") or {},
                         default_level=s.get("default_level", "protected"), trust=s.get("trust", "trusted"),
                         pseudonymize=list(s.get("pseudonymize") or []),
                         storage=s.get("storage", "external"),
                         label_field=s.get("label_field"), label_map={str(k): v for k, v in
                                                                     (s.get("label_map") or {}).items()})
            if any(src.level(None, f) == "secret" for f in src.pseudonymize):
                raise PolicyError(f"source {name}: secret fields use placeholders; don't pseudonymize them")
            if src.storage not in ("external", "boxes"):
                raise PolicyError(f"source {name}: storage must be external or boxes")
            if src.label_map and not src.label_field:
                raise PolicyError(f"source {name}: label_map needs label_field")
            for lvl in [*src.fields.values(), *src.key_levels.values(), src.default_level, *src.label_map.values()]:
                if lvl not in LEVELS:
                    raise PolicyError(f"source {name}: unknown level {lvl!r} (use {', '.join(LEVELS)})")
            if src.trust not in TRUST:
                raise PolicyError(f"source {name}: trust must be one of {TRUST}")
            sources[name] = src
        for name, src in sources.items():
            if src.owner != "company" and not any(o.owner == src.owner and o.owner_contact
                                                  for o in sources.values()):
                raise PolicyError(f"source {name}: owner {src.owner!r} needs an owner_contact "
                                  f"(on this source or another source with the same owner)")

        tasks: dict[str, TaskTemplate] = {}
        for name, t in (raw.get("tasks") or {}).items():
            t = t or {}
            _only(t, {"trusted", "reads", "sinks", "description"}, f"task {name}")
            _str_list(t.get("trusted"), f"task {name}: trusted")
            _mapping(t.get("reads"), f"task {name}: reads", entries=True)
            _mapping(t.get("sinks"), f"task {name}: sinks", entries=True)
            reads = t.get("reads") or {}
            for src, rule in reads.items():
                if src not in sources:
                    raise PolicyError(f"task {name}: unknown source {src!r}")
                _only(rule or {}, {"key", "keys", "fields"}, f"task {name} read {src}")
                _str_list((rule or {}).get("fields"), f"task {name} read {src}: fields")
                if "keys" in (rule or {}) and not isinstance(rule["keys"], list):
                    raise PolicyError(f"task {name} read {src}: keys must be a list, e.g. [a, b]")
            sinks = {}
            for sink, rule in (t.get("sinks") or {}).items():
                rule = rule or {}
                _only(rule, set(SinkRule.__dataclass_fields__), f"task {name} sink {sink}")
                where = f"task {name} sink {sink}"
                for key in ("allowed_recipients", "args", "invalidates"):
                    _str_list(rule.get(key), f"{where}: {key}", none_ok=key == "args")
                sa = rule.get("secrets_allowed")
                if sa is not None and not isinstance(sa, dict):
                    _str_list(sa, f"{where}: secrets_allowed")
                if rule.get("max_calls") is not None and (not isinstance(rule["max_calls"], int)
                                                          or isinstance(rule["max_calls"], bool)
                                                          or rule["max_calls"] < 0):
                    raise PolicyError(f"{where}: max_calls must be a whole number")
                if rule.get("recipient_arg") is not None and not isinstance(rule["recipient_arg"], str):
                    raise PolicyError(f"{where}: recipient_arg must be an argument name")
                sr = SinkRule(**rule)
                sr.allowed_recipients = list(sr.allowed_recipients or [])     # empty means nobody
                sr.invalidates = list(sr.invalidates or [])
                if sr.secrets_allowed is None:
                    sr.secrets_allowed = []
                if sr.approval not in ("never", "always"):
                    raise PolicyError(f"task {name} sink {sink}: approval must be never|always")
                if sr.risk not in ("low", "medium", "high"):
                    raise PolicyError(f"task {name} sink {sink}: risk must be low|medium|high")
                if sr.risk == "high":
                    if rule.get("approval") == "never":
                        raise PolicyError(f"task {name} sink {sink}: risk high needs approval")
                    sr.approval = "always"
                if sr.allowed_recipients and not sr.recipient_arg:
                    raise PolicyError(f"task {name} sink {sink}: allowed_recipients needs recipient_arg")
                sinks[sink] = sr
            tasks[name] = TaskTemplate(name=name, trusted=list(t.get("trusted") or []), reads=reads,
                                       sinks=sinks, description=t.get("description", ""))

        tools: dict[str, ToolMap] = {}
        for name, m in (raw.get("tools") or {}).items():
            _only(m or {}, {"read", "key_arg", "act", "description", "params"}, f"tool {name}")
            tm = ToolMap(name=name, **(m or {}))
            if bool(tm.read) == bool(tm.act):
                raise PolicyError(f"tool {name}: set exactly one of read / act")
            if tm.read and tm.read not in sources:
                raise PolicyError(f"tool {name}: unknown source {tm.read!r}")
            tools[name] = tm

        up = raw.get("upstream") or {}
        _only(up, {"sources", "sinks"}, "upstream")
        for kind in ("sources", "sinks"):
            for name, spec in (up.get(kind) or {}).items():
                _only(spec or {}, {"tool", "key_arg"}, f"upstream {kind} {name}")
                if not (spec or {}).get("tool"):
                    raise PolicyError(f"upstream {kind} {name}: needs 'tool'")
                if kind == "sources" and name not in sources:
                    raise PolicyError(f"upstream source {name!r} is not declared under sources")

        return cls(sources=sources, tasks=tasks, tools=tools,
                   internal_domains=[d.lower() for d in raw.get("internal_domains") or []],
                   cache_ttl_seconds=float(raw.get("cache_ttl_seconds", 300)),
                   detect_outbound=bool(raw.get("detect_outbound", False)), raw=raw)


def _only(d: dict, allowed: set[str], where: str) -> None:
    if extra := set(d) - allowed:
        raise PolicyError(f"{where}: unknown keys {sorted(extra)}")


def _mapping(v: Any, where: str, entries: bool = False) -> None:
    """None or a mapping; with entries=True, each value must be a mapping (or empty) too."""
    if v is None:
        return
    if not isinstance(v, dict):
        raise PolicyError(f"{where} must be a mapping (name: settings)")
    if entries:
        for k, item in v.items():
            if item is not None and not isinstance(item, dict):
                raise PolicyError(f"{where}: {k} must be a mapping (settings), not {type(item).__name__}")


def _str_list(v: Any, where: str, none_ok: bool = True) -> None:
    """A list of plain values. A bare string is rejected: iterating it would mean single characters
    (e.g. "*@acme.example" would contain '*', which allows every recipient)."""
    if v is None:
        return
    if not isinstance(v, list):
        raise PolicyError(f"{where} must be a list, e.g. [a, b] (got {type(v).__name__})")
    for item in v:
        if not isinstance(item, (str, int, float)) or isinstance(item, bool):
            raise PolicyError(f"{where}: list items must be plain values, not {type(item).__name__}")
