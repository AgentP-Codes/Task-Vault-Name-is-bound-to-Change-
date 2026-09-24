"""Behaviour baseline: learn what normal looks like, flag what doesn't.

This is the *detection* layer. It never blocks. It learns from audit logs of
tasks that finished without any block or would-block (so an attack can't teach
it that exfiltration is normal), and flags actions that differ from what each
task template has done before:

  * a sink this task has never used
  * more calls to a sink than ever seen in one task
  * a new kind of recipient (owner / internal / listed) for a sink
  * arguments never seen before, or much larger than usual

Flags go to the audit log (decision "flag") and your `on_flag` callback, and
show up in `taskvault review`. Until a template has `min_tasks` clean examples,
it's still learning and nothing is flagged.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


class Baseline:
    def __init__(self, profiles: dict[str, Any] | None = None, min_tasks: int = 20, size_factor: float = 3.0):
        self.profiles = profiles or {}
        self.min_tasks, self.size_factor = min_tasks, size_factor

    # ----------------------------------------------------------------- learn
    @classmethod
    def learn(cls, entries: list[dict[str, Any]], min_tasks: int = 20) -> Baseline:
        template_of: dict[Any, str] = {}
        dirty: set[Any] = set()
        acts: dict[Any, list[dict[str, Any]]] = defaultdict(list)
        for e in entries:
            t = e.get("task")
            if e.get("event") == "task.start":
                template_of[t] = e.get("template")
            elif e.get("decision") in ("block", "would_block"):
                dirty.add(t)
            elif e.get("event") == "act" and e.get("decision") == "allow":
                acts[t].append(e)

        profiles: dict[str, Any] = {}
        for task, template in template_of.items():
            if task in dirty or template is None:
                continue
            p = profiles.setdefault(template, {"tasks": 0, "sinks": {}})
            p["tasks"] += 1
            counts: dict[str, int] = defaultdict(int)
            for a in acts.get(task, []):
                s = p["sinks"].setdefault(a["sink"], {"max_calls": 0, "args": [], "recipient_classes": [],
                                                      "max_sizes": {}})
                counts[a["sink"]] += 1
                s["args"] = sorted(set(s["args"]) | set(a.get("args", [])))
                s["recipient_classes"] = sorted(set(s["recipient_classes"]) | set(a.get("recipient_classes", [])))
                for k, v in (a.get("arg_sizes") or {}).items():
                    s["max_sizes"][k] = max(s["max_sizes"].get(k, 0), v)
            for sink, n in counts.items():
                p["sinks"][sink]["max_calls"] = max(p["sinks"][sink]["max_calls"], n)
        return cls(profiles, min_tasks=min_tasks)

    # ----------------------------------------------------------------- check
    def check(self, template: str, sink: str, call_no: int, args: list[str], recipient_classes: list[str],
              sizes: dict[str, int]) -> list[str]:
        p = self.profiles.get(template)
        if not p or p["tasks"] < self.min_tasks:
            return []
        s = p["sinks"].get(sink)
        if s is None:
            return [f"first time a '{template}' task has used {sink}"]
        reasons = []
        if call_no > s["max_calls"]:
            reasons.append(f"{sink} called {call_no} times; never more than {s['max_calls']} before")
        if new := sorted(set(recipient_classes) - set(s["recipient_classes"])):
            reasons.append(f"new kind of recipient for {sink}: {', '.join(new)}")
        if new := sorted(set(args) - set(s["args"])):
            reasons.append(f"new arguments for {sink}: {', '.join(new)}")
        for k, v in sizes.items():
            usual = s["max_sizes"].get(k)
            if usual and v > usual * self.size_factor + 50:
                reasons.append(f"'{k}' is {v} characters; usually at most {usual}")
        return reasons

    # ------------------------------------------------------------------- io
    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps({"min_tasks": self.min_tasks, "profiles": self.profiles}, indent=2))

    @classmethod
    def load(cls, path: str | Path) -> Baseline:
        data = json.loads(Path(path).read_text())
        return cls(data.get("profiles", {}), min_tasks=data.get("min_tasks", 20))

    def summary(self) -> list[str]:
        out = []
        for t, p in sorted(self.profiles.items()):
            state = "active" if p["tasks"] >= self.min_tasks else f"learning ({p['tasks']}/{self.min_tasks})"
            sinks = ", ".join(f"{s} (max {v['max_calls']}/task)" for s, v in sorted(p["sinks"].items())) or "none"
            out.append(f"{t}: {p['tasks']} clean tasks, {state}; sinks: {sinks}")
        return out
