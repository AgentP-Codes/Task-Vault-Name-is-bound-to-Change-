"""`taskvault setup`: scan your data and write a starter policy for you.

It looks at databases, table files, document folders and MCP servers, works
out which fields are sensitive and who owns each record, and writes:

  taskvault.yaml        the policy, with a comment on every decision
  fixtures.yaml         SYNTHETIC sample data for `taskvault test` (never copies real values)
  taskvault_app.py      connector code that wires the vault to what was scanned
  setup-report.md       what was found and what to review

Everything runs locally. Sample values are read only to classify fields and are
never written anywhere; the report contains counts and reasons, not data.
The result is a draft: review it before turning enforcement on.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .connectors.files import FolderDocuments, read_table
from .detect import Finding, classify_column, classify_document

PSEUDONYM_KINDS = {"person_name", "email", "phone", "address"}


@dataclass
class ScannedSource:
    name: str
    kind: str                                   # "table" | "documents"
    origin: str                                 # e.g. sqlite:///crm.db#customers, file path, folder
    key: str | None = None
    columns: dict[str, Finding] = field(default_factory=dict)
    documents: dict[str, Finding] = field(default_factory=dict)
    rows_sampled: int = 0
    foreign_keys: dict[str, str] = field(default_factory=dict)   # column -> referenced table
    owner: str = "company"
    owner_contact: str | None = None
    owner_field: str | None = None
    table: str | None = None


@dataclass
class ScannedTool:
    name: str
    description: str
    params: list[str]
    role: str                                   # "read" | "act"
    key_arg: str | None = None
    recipient_arg: str | None = None
    risk: str = "low"


# --------------------------------------------------------------------- scanning
def _singular(word: str) -> str:
    w = word.lower()
    if w.endswith("ies"):
        return w[:-3] + "y"
    if w.endswith("ses") or w.endswith("xes"):
        return w[:-2]
    return w[:-1] if w.endswith("s") and not w.endswith("ss") else w


def _guess_key(columns: list[str], rows: list[dict[str, Any]], table: str) -> str | None:
    prefer = ["id", f"{_singular(table)}_id", "uuid", "key", "number", "name", "slug"]
    for p in prefer:
        for c in columns:
            if c.lower() == p:
                vals = [r.get(c) for r in rows]
                if len(set(map(str, vals))) == len(vals):
                    return c
    for c in columns:
        vals = [str(r.get(c)) for r in rows]
        if vals and len(set(vals)) == len(vals) and c.lower().endswith("id"):
            return c
    return columns[0] if columns else None


def scan_rows(name: str, origin: str, rows: list[dict[str, Any]], key: str | None = None,
              foreign_keys: dict[str, str] | None = None, table: str | None = None) -> ScannedSource:
    columns = list(rows[0]) if rows else []
    src = ScannedSource(name=name, kind="table", origin=origin, rows_sampled=len(rows),
                        foreign_keys=foreign_keys or {}, table=table)
    src.key = key or _guess_key(columns, rows, table or name.split(".")[-1])
    for c in columns:
        f = classify_column(c, [r.get(c) for r in rows])
        if c == src.key and f.level != "secret":
            f = Finding("identifier", "normal", max(f.confidence, 0.8), [f"record key; {'; '.join(f.reasons)}"])
        src.columns[c] = f
    return src


def scan_sqlite(path: str | Path, sample: int = 200) -> list[ScannedSource]:
    conn = sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    out = []
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        for t in tables:
            q = t.replace('"', '""')
            info = conn.execute(f'PRAGMA table_info("{q}")').fetchall()
            pk = next((r["name"] for r in info if r["pk"] == 1), None)
            fks = {r["from"]: r["table"] for r in conn.execute(f'PRAGMA foreign_key_list("{q}")').fetchall()}
            rows = [dict(r) for r in conn.execute(f'SELECT * FROM "{q}" LIMIT ?', (sample,))]  # noqa: S608
            if not rows:
                rows = [{r["name"]: None for r in info}]
            out.append(scan_rows(f"db.{t}", f"sqlite:///{path}#{t}", rows, pk, fks, table=t))
    finally:
        conn.close()
    return out


def scan_postgres(dsn: str, sample: int = 200, schema: str = "public") -> list[ScannedSource]:
    import psycopg  # optional: pip install psycopg

    out = []
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema=%s "
                    "AND table_type='BASE TABLE' ORDER BY table_name", (schema,))
        for (t,) in cur.fetchall():
            cur.execute("""SELECT kcu.column_name, tc.constraint_type, ccu.table_name
                           FROM information_schema.table_constraints tc
                           JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
                           LEFT JOIN information_schema.constraint_column_usage ccu
                             ON tc.constraint_name = ccu.constraint_name AND tc.constraint_type = 'FOREIGN KEY'
                           WHERE tc.table_schema=%s AND tc.table_name=%s""", (schema, t))
            cons = cur.fetchall()
            pk = next((c for c, typ, _ in cons if typ == "PRIMARY KEY"), None)
            fks = {c: ref for c, typ, ref in cons if typ == "FOREIGN KEY" and ref}
            ident = '"' + t.replace('"', '""') + '"'
            cur.execute(f"SELECT * FROM {schema}.{ident} LIMIT %s", (sample,))  # noqa: S608
            names = [d[0] for d in cur.description]
            rows = [dict(zip(names, r, strict=False)) for r in cur.fetchall()] or [{n: None for n in names}]
            out.append(scan_rows(f"db.{t}", f"postgresql#{t}", rows, pk, fks, table=t))
    return out


def scan_file(path: str | Path, sample: int = 200) -> ScannedSource:
    path = Path(path)
    rows = read_table(path)[:sample]
    return scan_rows(f"file.{re.sub(r'[^a-z0-9_]', '_', path.stem.lower())}", str(path), rows)


def scan_documents(folder: str | Path) -> ScannedSource:
    folder = Path(folder)
    docs = FolderDocuments(folder)
    src = ScannedSource(name=f"docs.{re.sub(r'[^a-z0-9_]', '_', folder.name.lower()) or 'docs'}",
                        kind="documents", origin=str(folder))
    for key in docs.keys():
        rec = docs(key)
        if rec:
            src.documents[key] = classify_document(key, rec["body"])
    return src


READ_VERBS = ("get", "read", "fetch", "lookup", "find", "search", "list", "query", "retrieve", "show")
HIGH_VERBS = ("delete", "remove", "refund", "pay", "transfer", "charge", "cancel", "drop", "wire")
MEDIUM_VERBS = ("update", "create", "insert", "set", "write", "modify", "post", "upload", "schedule")
RECIPIENT_PARAMS = ("to", "recipient", "recipients", "email", "address", "channel", "phone", "cc", "bcc")


def classify_tool(name: str, description: str, params: list[str]) -> ScannedTool:
    verb = re.split(r"[_\-.]|(?<=[a-z])(?=[A-Z])", name)[0].lower()
    key_arg = next((p for p in params if p == "id" or p.endswith("_id") or p in ("name", "key", "slug")), None)
    recipient = next((p for p in params if p.lower() in RECIPIENT_PARAMS), None)
    if verb in READ_VERBS and not recipient:
        return ScannedTool(name, description, params, "read", key_arg=key_arg)
    risk = "high" if verb in HIGH_VERBS else "medium" if verb in MEDIUM_VERBS else "low"
    return ScannedTool(name, description, params, "act", recipient_arg=recipient, risk=risk)


def scan_mcp(command: list[str]) -> list[ScannedTool]:
    from .mcp import StdioMCPClient

    client = StdioMCPClient(command)
    try:
        tools = client.request("tools/list").get("tools", [])
    finally:
        client.close()
    return [classify_tool(t["name"], t.get("description", ""),
                          list(((t.get("inputSchema") or {}).get("properties") or {}).keys())) for t in tools]


# ---------------------------------------------------------------- inference
def infer_owners(sources: list[ScannedSource]) -> None:
    """Tables with an email column are 'owner' tables; tables pointing at them belong to that owner."""
    owners: dict[str, ScannedSource] = {}
    for s in sources:
        if s.kind != "table" or not s.key:
            continue
        email = next((c for c, f in s.columns.items() if f.kind == "email"), None)
        if email:
            base = _singular(s.table or s.name.split(".")[-1])
            s.owner, s.owner_contact = f"{base}_id", email
            owners[(s.table or s.name.split(".")[-1]).lower()] = s
    for s in sources:
        if s.kind != "table" or s.owner != "company":
            continue
        for col, ref in s.foreign_keys.items():
            if ref.lower() in owners:
                s.owner, s.owner_field = owners[ref.lower()].owner, col
                break
        else:
            for col in s.columns:
                for tname, o in owners.items():
                    if col.lower() in (f"{_singular(tname)}_id", o.owner):
                        s.owner, s.owner_field = o.owner, col
                        break
                if s.owner != "company":
                    break


# ------------------------------------------------------------------ writing
def _y(v: Any) -> str:
    return json.dumps(v)     # JSON scalars and lists are valid YAML


def _ident(name: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", name.lower())


def build_policy(sources: list[ScannedSource], tools: list[ScannedTool], domain: str,
                 pseudonyms: bool = True) -> str:
    L = ["# taskvault policy - DRAFT written by `taskvault setup`.",
         "# Every decision below has a comment saying why. Review them, then run:",
         "#   taskvault check && taskvault test",
         "# Levels: secret = model never sees it | protected = only goes to its owner | normal = anywhere",
         "", "version: 1", f"internal_domains: [{_y(domain)}]"
         + ("   # TODO: set your company's email domain(s)" if domain == "example.com" else ""),
         "cache_ttl_seconds: 300",
         "detect_outbound: true   # also block outbound text that looks like a card, TFN, key...", "",
         "sources:"]
    for s in sources:
        L.append(f"  {s.name}:")
        L.append(f"    # scanned from {s.origin}" + (f" ({s.rows_sampled} rows sampled)" if s.kind == "table" else ""))
        if s.kind == "documents":
            L += ["    owner: company", "    default_level: protected   # documents not listed are internal",
                  "    key_levels:"]
            for k, f in s.documents.items():
                L.append(f"      {_y(k)}: {f.level}   # {'; '.join(f.reasons)}")
            if not s.documents:
                L[-1] = "    key_levels: {}"
            continue
        if s.owner != "company":
            why = (f"has an email column ({s.owner_contact})" if s.owner_contact
                   else f"'{s.owner_field}' links each row to its owner")
            L.append(f"    owner: {s.owner}   # each record belongs to one person/customer: {why}")
            if s.owner_contact:
                L.append(f"    owner_contact: {s.owner_contact}")
            if s.owner_field:
                L.append(f"    owner_field: {s.owner_field}")
        else:
            L.append("    owner: company   # no owner column found: treated as company data")
        L.append("    fields:")
        for c, f in s.columns.items():
            L.append(f"      {_y(c)}: {f.level}   # {f.label} ({int(f.confidence * 100)}%): {'; '.join(f.reasons)}")
        pseudo = [c for c, f in s.columns.items() if f.kind in PSEUDONYM_KINDS and f.level == "protected"]
        if pseudonyms and pseudo:
            L.append(f"    pseudonymize: {_y(pseudo)}   # the model sees stand-ins; real values only at sinks")

    L += ["", "tasks:"]
    owner_tables = [s for s in sources if s.kind == "table" and s.owner_contact and s.key]
    docs = [s for s in sources if s.kind == "documents"]
    act_tools = [t for t in tools if t.role == "act"]
    if not owner_tables:
        L += ["  # No table with a clear owner (e.g. customers with an email column) was found.",
              "  # Add a task by hand; see docs/policy-reference.md.", "  {}"]
    for s in owner_tables:
        tname = f"{_singular(s.table or s.name.split('.')[-1])}_request"
        public_docs = [(d, [k for k, f in d.documents.items() if f.level == "normal"]) for d in docs]
        L += [f"  {tname}:",
              f"    description: Handle one request for a single {_singular(s.table or 'record')}.",
              f"    trusted: [{s.owner}]   # your app must set this from a verified sender or login, never from text",
              "    reads:",
              f"      {s.name}:",
              f"        key: {_y('{' + s.owner + '}')}",
              f"        fields: {_y(list(s.columns))}"]
        for d, keys in public_docs:
            if keys:
                L += [f"      {d.name}:", f"        keys: {_y(keys)}", "        fields: [name, body]"]
        related = [o.name for o in sources if o.owner == s.owner and o is not s and o.kind == "table"]
        if related:
            L.append(f"      # also linked to this owner: {', '.join(related)} "
                     "(add a read with a trusted key if needed)")
        L += ["    sinks:",
              "      email.send:",
              "        recipient_arg: to",
              f"        allowed_recipients: [{_y(f'{s.name}:{{{s.owner}}}.{s.owner_contact}')}, {_y('*@' + domain)}]",
              "        args: [to, subject, body]",
              "        max_calls: 3"]
        for t in act_tools:
            L.append(f"      mcp.{t.name}:   # from MCP tool '{t.name}' ({t.risk} risk from its name)")
            if t.recipient_arg:
                L += [f"        recipient_arg: {t.recipient_arg}",
                      f"        allowed_recipients: [{_y(f'{s.name}:{{{s.owner}}}.{s.owner_contact}')}]"]
            L += [f"        args: {_y(t.params)}", f"        risk: {t.risk}", "        max_calls: 3"]

    L += ["", "tools:"]
    for s in owner_tables:
        base = _singular(s.table or s.name.split(".")[-1])
        L.append(f"  get_{base}: {{read: {s.name}, key_arg: {s.owner}, "
                 f"description: {_y(f'Look up the {base} this task is about.')}}}")
    for d in docs:
        L.append(f"  get_{_ident(d.name.split('.')[-1])}_doc: {{read: {d.name}, key_arg: name, "
                 f"description: \"Read a document by name.\"}}")
    L.append("  send_email: {act: email.send, description: \"Send an email.\", "
             "params: {to: string, subject: string, body: string}}")
    for t in act_tools:
        L.append(f"  {t.name}: {{act: mcp.{t.name}, description: {_y(t.description or t.name)}, "
                 f"params: {_y({p: 'string' for p in t.params})}}}")
    if tools:
        L += ["", "upstream:   # for `taskvault serve` in front of the scanned MCP server", "  sources: {}",
              "  sinks:"]
        for t in act_tools:
            L.append(f"    mcp.{t.name}: {{tool: {t.name}}}")
        reads = [t for t in tools if t.role == "read"]
        if reads:
            L.append("  # read tools found (map each to a source above if it returns one record):")
            L += [f"  #   {t.name}({', '.join(t.params)})" for t in reads]
    return "\n".join(L) + "\n"


# ------------------------------------------------------------ synthetic data
FIRST = ["Alex", "Sam", "Jordan", "Riley"]
LAST = ["Taylor", "Morgan", "Lee", "Patel"]
SYNTH: dict[str, Callable[[int], Any]] = {
    "card_number": lambda i: ["4111 1111 1111 1111", "5555 5555 5555 4444", "3782 822463 10005"][i % 3],
    "au_tfn": lambda i: ["123 456 782", "876 543 210"][i % 2],
    "au_medicare": lambda i: "2123 45670 1",
    "bank_account": lambda i: f"062-000 1234567{i}",
    "iban": lambda i: "GB82 WEST 1234 5698 7654 32",
    "api_key": lambda i: f"sk-test-{'x' * 24}{i}",
    "private_key": lambda i: "-----BEGIN PRIVATE KEY-----(synthetic)",
    "password": lambda i: f"synthetic-secret-{i}",
    "gov_id": lambda i: f"PA{1000000 + i}",
    "au_abn": lambda i: "51 824 753 556",
    "email": lambda i: f"{FIRST[i % 4].lower()}.{LAST[i % 4].lower()}{i}@example.com",
    "phone": lambda i: f"+61 400 000 {100 + i}",
    "person_name": lambda i: f"{FIRST[i % 4]} {LAST[i % 4]}",
    "address": lambda i: f"{10 + i} Example St, Sampletown NSW",
    "dob": lambda i: f"199{i}-01-01",
    "ip_address": lambda i: f"192.0.2.{10 + i}",
    "money": lambda i: f"{100 * (i + 1)}.00",
    "free_text": lambda i: f"Synthetic note {i}",
    "identifier": lambda i: 1001 + i,
    "category": lambda i: ["standard", "premium"][i % 2],
    "timestamp": lambda i: "2026-01-01T00:00:00Z",
}


def build_fixtures(sources: list[ScannedSource]) -> str:
    records: dict[str, dict[str, Any]] = {}
    trusted: dict[str, dict[str, Any]] = {}
    owner_ids: dict[str, list[Any]] = {}
    for s in sources:
        if s.kind == "table" and s.owner_contact and s.key:
            owner_ids[s.owner] = [SYNTH["identifier"](i) for i in range(2)]
    for s in sources:
        recs: dict[str, Any] = {}
        if s.kind == "documents":
            for k, f in s.documents.items():
                recs[k] = {"name": k, "body": f"Synthetic {f.level} document '{k}'"
                           + (" - INTERNAL ONLY" if f.level != "normal" else "")}
        else:
            for i in range(2):
                row = {c: SYNTH[f.kind](i) for c, f in s.columns.items()}
                if s.owner_field and s.owner in owner_ids:
                    row[s.owner_field] = owner_ids[s.owner][i]
                if s.key:
                    row[s.key] = SYNTH["identifier"](i) if s.key not in (s.owner_field,) else row[s.key]
                recs[str(row.get(s.key, i))] = row
        records[s.name] = recs
        if s.kind == "table" and s.owner_contact and s.key:
            trusted[f"{_singular(s.table or s.name.split('.')[-1])}_request"] = {s.owner: SYNTH["identifier"](0)}
    body = {"attacker": "exfil@attacker.example", "trusted": trusted, "sources": records}
    return ("# SYNTHETIC test data for `taskvault test`, generated by `taskvault setup`.\n"
            "# No real values were copied. Test card numbers are standard payment-network test numbers.\n"
            + json.dumps(body, indent=2) + "\n")


def build_app(sources: list[ScannedSource]) -> str:
    L = ['"""Connectors for the vault, generated by `taskvault setup`. Edit to point at your real systems."""',
         "", "import sqlite3", "", "from taskvault import AuditLog, Policy, Vault",
         "from taskvault.connectors import FolderDocuments, TableFile, SQLConnector", "",
         "", "def build_vault(sinks: dict) -> Vault:",
         '    """`sinks` maps each sink name in taskvault.yaml to a function, e.g. {"email.send": send_email}."""',
         "    sources = {"]
    for s in sources:
        if s.kind == "documents":
            L.append(f"        {_y(s.name)}: FolderDocuments({_y(s.origin)}),")
        elif s.origin.startswith("sqlite:///") and s.table:
            path = s.origin[len("sqlite:///"):].split("#")[0]
            L.append(f"        {_y(s.name)}: SQLConnector(lambda: sqlite3.connect({_y(path)}), {_y(s.table)}, "
                     f"{_y(s.key)}, columns={_y(list(s.columns))}),")
        elif s.origin.startswith("postgresql"):
            L.append(f"        # {s.name}: SQLConnector(lambda: psycopg.connect(DSN), {_y(s.table)}, {_y(s.key)}, "
                     f"columns={_y(list(s.columns))}, paramstyle='format'),")
        else:
            L.append(f"        {_y(s.name)}: TableFile({_y(s.origin)}, {_y(s.key)}),")
    L += ["    }", '    return Vault(Policy.load("taskvault.yaml"), sources, sinks, audit=AuditLog("audit.jsonl"))', ""]
    return "\n".join(L)


def build_report(sources: list[ScannedSource], tools: list[ScannedTool], checks: list[str]) -> str:
    L = ["# taskvault setup report", "", "What the scanner found. No data values are included here.", ""]
    for s in sources:
        L += [f"## {s.name}", "", f"Scanned from `{s.origin}`.", ""]
        if s.kind == "documents":
            L += ["| Document | Level | Why |", "| --- | --- | --- |"]
            L += [f"| {k} | {f.level} | {'; '.join(f.reasons)} |" for k, f in s.documents.items()]
        else:
            owner = f"{s.owner} (contact: {s.owner_contact or 'via ' + str(s.owner_field)})" \
                if s.owner != "company" else "company"
            L += [f"Key: `{s.key}` · Owner: {owner} · Rows sampled: {s.rows_sampled}", "",
                  "| Field | Detected as | Level | Confidence | Why |", "| --- | --- | --- | --- | --- |"]
            L += [f"| {c} | {f.label} | {f.level} | {int(f.confidence * 100)}% | {'; '.join(f.reasons)} |"
                  for c, f in s.columns.items()]
            low = [c for c, f in s.columns.items() if f.confidence < 0.6]
            if low:
                L += ["", f"**Review:** low confidence for {', '.join(low)}."]
        L.append("")
    if tools:
        L += ["## MCP tools", "", "| Tool | Role | Risk | Recipient arg |", "| --- | --- | --- | --- |"]
        L += [f"| {t.name} | {t.role} | {t.risk if t.role == 'act' else '-'} | {t.recipient_arg or '-'} |"
              for t in tools]
        L.append("")
    L += ["## Checks", ""] + [f"- {c}" for c in checks] + [""]
    return "\n".join(L)


# ---------------------------------------------------------------------- run
def run_setup(out_dir: str | Path, sqlite: list[str] | None = None, postgres: list[str] | None = None,
              files: list[str] | None = None, docs: list[str] | None = None, mcp: list[str] | None = None,
              domain: str = "example.com", pseudonyms: bool = True, force: bool = False,
              echo: Callable[[str], None] = print) -> int:
    from .attacks import Fixtures, run_attack_suite
    from .policy import Policy

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    targets = {n: out / n for n in ("taskvault.yaml", "fixtures.yaml", "taskvault_app.py", "setup-report.md")}
    if not force and (existing := [str(p) for p in targets.values() if p.exists()]):
        echo(f"won't overwrite {', '.join(existing)} (use --force)")
        return 1

    sources: list[ScannedSource] = []
    for p in sqlite or []:
        echo(f"scanning database {p} ...")
        sources += scan_sqlite(p)
    for dsn in postgres or []:
        echo("scanning postgres ...")
        sources += scan_postgres(dsn)
    for f in files or []:
        echo(f"scanning file {f} ...")
        sources.append(scan_file(f))
    for d in docs or []:
        echo(f"scanning documents in {d} ...")
        sources.append(scan_documents(d))
    tools = scan_mcp(mcp) if mcp else []
    if not sources and not tools:
        echo("nothing to scan: pass --sqlite, --postgres, --file, --docs or --mcp")
        return 2
    infer_owners(sources)

    policy_text = build_policy(sources, tools, domain, pseudonyms)
    fixtures_text = build_fixtures(sources)
    targets["taskvault.yaml"].write_text(policy_text)
    targets["fixtures.yaml"].write_text(fixtures_text)
    targets["taskvault_app.py"].write_text(build_app(sources))

    checks = []
    policy = Policy.load(targets["taskvault.yaml"])
    checks.append(f"policy valid: {len(policy.sources)} sources, {len(policy.tasks)} tasks")
    report = run_attack_suite(policy, Fixtures.load(targets["fixtures.yaml"]))
    checks.append(f"attack suite on synthetic data: {report.summary()}")
    checks += [f"warning: {w}" for w in report.warnings]
    if domain == "example.com":
        checks.append("TODO: set internal_domains to your company's email domain")
    targets["setup-report.md"].write_text(build_report(sources, tools, checks))

    fields = sum(len(s.columns) for s in sources)
    counts = {lvl: sum(f.level == lvl for s in sources for f in s.columns.values())
              for lvl in ("secret", "protected", "normal")}
    echo(f"\nscanned {len(sources)} sources, {fields} fields: {counts['secret']} secret, "
         f"{counts['protected']} protected, {counts['normal']} normal")
    for c in checks:
        echo(f"  {c}")
    echo("\nwrote " + ", ".join(str(p) for p in targets.values()))
    echo("next: review taskvault.yaml (every choice has a comment), then run `taskvault test`")
    return 1 if report.leaks else 0
