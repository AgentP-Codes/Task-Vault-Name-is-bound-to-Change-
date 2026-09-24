"""Session traces and replay.

A trace records what one task saw: its template, trusted inputs, the untrusted
inputs handed to the agent (e.g. a ticket body), every source record fetched and
every action taken. Traces hold real data, so they're encrypted when the vault
has a cipher, and they expire after a retention period unless pinned.

Replay reruns an agent against a trace with every tool stubbed from the
recording: nothing reaches the real world. Remove a suspect span of text, run
several times, and compare outcomes to find the *likely* cause of an action.
Model outputs vary between runs, so results are reported as frequencies.

Replays never write to the main audit log except for one entry per replay job;
their results go to a separate investigation store.
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .crypto import Cipher
from .policy import Policy
from .vault import Blocked, Task, Vault

AgentFn = Callable[[Task, dict[str, Any]], Any]


@dataclass
class Trace:
    id: str
    template: str = ""
    trusted: dict[str, Any] = field(default_factory=dict)
    inputs: dict[str, Any] = field(default_factory=dict)       # untrusted inputs given to the agent
    reads: list[dict[str, Any]] = field(default_factory=list)  # {source, key, record}
    actions: list[dict[str, Any]] = field(default_factory=list)  # {sink, args, result}
    created: float = field(default_factory=time.time)
    pinned: bool = False

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class Recorder:
    """Pass to `Vault(recorder=...)` to capture a trace of each task."""

    def __init__(self) -> None:
        self.trace = Trace(id=_new_id())

    def task_started(self, template: str, trusted: dict[str, Any]) -> None:
        self.trace.template, self.trace.trusted = template, dict(trusted)

    def add_input(self, name: str, value: Any) -> None:
        self.trace.inputs[name] = value

    def source_read(self, source: str, key: Any, record: dict | None) -> None:
        self.trace.reads.append({"source": source, "key": key, "record": record})

    def sink_called(self, sink: str, args: dict[str, Any], result: Any) -> None:
        self.trace.actions.append({"sink": sink, "args": args, "result": _jsonable(result)})


class TraceStore:
    """Traces on disk, encrypted with the customer's key when a cipher is given."""

    def __init__(self, root: str | Path, cipher: Cipher | None = None, retention_days: float = 30):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.cipher, self.retention = cipher, retention_days * 86400

    def _path(self, trace_id: str) -> Path:
        if not trace_id.isalnum():
            raise ValueError("bad trace id")
        return self.root / f"{trace_id}.trace"

    def save(self, trace: Trace) -> str:
        data = trace.to_dict()
        blob = self.cipher.encrypt(data, aad=trace.id) if self.cipher else json.dumps(data, default=str).encode()
        self._path(trace.id).write_bytes(blob)
        return trace.id

    def load(self, trace_id: str) -> Trace:
        blob = self._path(trace_id).read_bytes()
        data = self.cipher.decrypt(blob, aad=trace_id) if self.cipher else json.loads(blob)
        return Trace(**data)

    def list(self) -> list[str]:
        return sorted(p.stem for p in self.root.glob("*.trace"))

    def pin(self, trace_id: str, pinned: bool = True) -> None:
        t = self.load(trace_id)
        t.pinned = pinned
        self.save(t)

    def purge(self, now: float | None = None) -> int:
        now = now or time.time()
        removed = 0
        for tid in self.list():
            t = self.load(tid)
            if not t.pinned and now - t.created > self.retention:
                self._path(tid).unlink()
                removed += 1
        return removed


# ----------------------------------------------------------------------- replay
@dataclass
class RunOutcome:
    actions: list[tuple[str, str]]     # (sink, recipient) pairs that would have happened
    blocked: list[str]
    error: str | None = None


def replay_once(policy: Policy, trace: Trace, agent: AgentFn, remove: list[str] | None = None,
                mode: str = "enforce") -> RunOutcome:
    remove = remove or []
    recorded: dict[tuple[str, str], Any] = {}
    for r in trace.reads:
        recorded[(r["source"], str(r["key"]))] = _strip(r["record"], remove)
    captured: list[tuple[str, str]] = []

    def make_source(name: str) -> Callable[[Any], Any]:
        return lambda key: recorded.get((name, str(key)))

    def make_sink(name: str) -> Callable[..., Any]:
        rule_args = [t.sinks[name].recipient_arg for t in policy.tasks.values()
                     if name in t.sinks and t.sinks[name].recipient_arg]

        def sink(**args: Any) -> Any:
            who = next((str(args.get(a)) for a in rule_args if a in args), "")
            captured.append((name, who))
            return {"replayed": True}
        return sink

    sinks = {a["sink"] for a in trace.actions} | {s for t in policy.tasks.values() for s in t.sinks}
    audit = AuditLog()
    vault = Vault(policy, sources={s: make_source(s) for s in policy.sources},
                  sinks={s: make_sink(s) for s in sinks}, audit=audit, mode=mode)
    task = vault.start_task(trace.template, **trace.trusted)
    error = None
    try:
        agent(task, _strip(trace.inputs, remove))
    except Blocked:
        pass
    except Exception as e:  # noqa: BLE001 - an agent crash is an outcome worth reporting
        error = f"{type(e).__name__}: {e}"
    return RunOutcome(captured, [e["reason"] for e in audit.decisions("block")], error)


def investigate(policy: Policy, trace: Trace, agent: AgentFn, remove: list[str], runs: int = 5,
                store: str | Path | None = None, audit: AuditLog | None = None,
                started_by: str = "cli") -> dict[str, Any]:
    """Compare `runs` replays with and without the suspect text. One audit entry per job."""
    baseline = [replay_once(policy, trace, agent) for _ in range(runs)]
    modified = [replay_once(policy, trace, agent, remove=remove) for _ in range(runs)]

    def freq(outcomes: list[RunOutcome]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for o in outcomes:
            for a in set(o.actions):
                key = f"{a[0]} -> {a[1]}" if a[1] else a[0]
                counts[key] = counts.get(key, 0) + 1
            for b in set(o.blocked):
                counts["BLOCKED: " + b] = counts.get("BLOCKED: " + b, 0) + 1
        return counts

    base, mod = freq(baseline), freq(modified)
    findings = []
    for k in sorted(set(base) | set(mod)):
        b, m = base.get(k, 0), mod.get(k, 0)
        if b != m:
            confidence = abs(b - m) / runs
            findings.append({"event": k, "with_text": f"{b}/{runs}", "without_text": f"{m}/{runs}",
                             "likely_caused_by_removed_text": b > m, "confidence": round(confidence, 2)})
    result = {"id": _new_id(), "trace": trace.id, "removed": [f"<{len(r)} chars>" for r in remove],
              "runs": runs, "created": time.time(), "findings": findings,
              "baseline": base, "modified": mod,
              "errors": sorted({o.error for o in baseline + modified if o.error})}
    if store:
        root = Path(store)
        root.mkdir(parents=True, exist_ok=True)
        (root / f"{result['id']}.json").write_text(json.dumps(result, indent=2))
    if audit is not None:
        audit.record("replay", trace=trace.id, investigation=result["id"], runs=runs, started_by=started_by)
    return result


def _strip(value: Any, remove: list[str]) -> Any:
    if not remove:
        return value
    if isinstance(value, str):
        for r in remove:
            value = value.replace(r, "")
        return value
    if isinstance(value, list):
        return [_strip(v, remove) for v in value]
    if isinstance(value, dict):
        return {k: _strip(v, remove) for k, v in value.items()}
    return value


def _jsonable(v: Any) -> Any:
    try:
        json.dumps(v)
        return v
    except (TypeError, ValueError):
        return str(v)


def _new_id() -> str:
    return time.strftime("%Y%m%d%H%M%S") + secrets.token_hex(4)
