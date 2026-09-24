"""taskvault - a task-scoped data vault for AI agents (working name).

Core:      Vault, Task, Policy, Blocked, AuditLog
Planner:   taskvault.planner.Planner (provenance-tracked, CaMeL-style)
Storage:   taskvault.crypto (customer-held keys), taskvault.cache (read-through)
Adapters:  taskvault.connectors, taskvault.mcp (proxy), taskvault.llm (models)
Tooling:   taskvault.attacks (attack suite), taskvault.traces (replay), `taskvault` CLI
"""

__version__ = "0.4.2"

from .audit import AuditLog  # noqa: E402
from .policy import Policy, PolicyError  # noqa: E402
from .vault import ApprovalRequest, Blocked, SinkError, Task, Vault  # noqa: E402

__all__ = ["ApprovalRequest", "AuditLog", "Blocked", "Policy", "PolicyError", "SinkError", "Task", "Vault",
           "__version__"]
