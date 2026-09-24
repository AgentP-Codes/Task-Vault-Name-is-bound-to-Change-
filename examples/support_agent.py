"""A real support agent behind taskvault: Postgres CRM, SMTP email, Claude as the model.

    pip install "taskvault[anthropic]" psycopg
    taskvault keys init ./customer.key
    export ANTHROPIC_API_KEY=... DATABASE_URL=postgresql://...
    python examples/support_agent.py 12 "I was charged twice, can I get a refund?"

Your app decides the trusted inputs (here: the verified customer id of the
ticket sender). The ticket text is untrusted and goes to the model as data.
"""

import os
import sys

from taskvault import AuditLog, Policy, Vault
from taskvault.cache import EncryptedCache
from taskvault.connectors import RESTSink, SMTPSink, SQLConnector
from taskvault.connectors.base import HttpClient
from taskvault.crypto import Cipher, LocalKeyProvider
from taskvault.llm import AnthropicProvider, ToolAgent


def build_vault() -> Vault:
    import psycopg  # your driver of choice

    connect = lambda: psycopg.connect(os.environ["DATABASE_URL"])  # noqa: E731
    cipher = Cipher(LocalKeyProvider("customer.key", create=False))
    policy = Policy.load("taskvault.yaml")          # e.g. from `taskvault init --template support`
    return Vault(
        policy,
        sources={
            "crm.customer": SQLConnector(connect, "customers", key_column="id",
                                         columns=["name", "email", "phone", "plan", "card_number"],
                                         paramstyle="format"),
            "docs": SQLConnector(connect, "help_articles", key_column="slug", columns=["name", "body"],
                                 paramstyle="format"),
            "inbox.ticket": lambda key: None,        # the ticket is passed to the agent directly below
        },
        sinks={
            "email.send": SMTPSink(os.environ.get("SMTP_HOST", "smtp.example.com"),
                                   username=os.environ.get("SMTP_USER"), password=os.environ.get("SMTP_PASS"),
                                   sender="support@yourcompany.com"),
            "payments.refund": RESTSink(HttpClient("https://payments.yourcompany.com/api",
                                                   token=os.environ.get("PAYMENTS_TOKEN")),
                                        "POST", "/refunds", allowed_args=["card", "amount"]),
        },
        audit=AuditLog("audit.jsonl"),
        cipher=cipher,
        cache=EncryptedCache(cipher, ttl_seconds=policy.cache_ttl_seconds),
        approver=lambda req: input(f"Approve {req.sink} {req.args}? [y/N] ").lower() == "y",
    )


if __name__ == "__main__":
    customer_id, ticket = int(sys.argv[1]), sys.argv[2]
    task = build_vault().start_task("support_reply", customer_id=customer_id)
    agent = ToolAgent(AnthropicProvider())
    print(agent(task, {"ticket": ticket}))
    for tool, _args, outcome in agent.log:
        print(f"  {outcome:<8} {tool}")
