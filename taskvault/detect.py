"""Automatic detection of sensitive data.

Used by `taskvault setup` to label fields without the developer doing it by
hand, by `taskvault scan` to find secrets in text, and (optionally) by the vault
to block outbound values that look like secrets.

Detection is a *suggestion*: setup writes what it found, with its reasons and
confidence, into the policy as comments so a person can review it. Enforcement
always comes from the policy, never from detection alone.

Checksums are verified where the format has one (cards, TFN, ABN, Medicare,
IBAN), which keeps false positives low.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

# ------------------------------------------------------------------ checksums


def _digits(s: str) -> str:
    return re.sub(r"[\s-]", "", s)


def luhn_ok(num: str) -> bool:
    d = _digits(num)
    if not d.isdigit() or not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0 and len(set(d)) > 1


def tfn_ok(num: str) -> bool:
    d = _digits(num)
    if not d.isdigit() or len(d) not in (8, 9):
        return False
    weights = [10, 7, 8, 4, 6, 3, 5, 1] if len(d) == 8 else [1, 4, 3, 7, 5, 8, 6, 9, 10]
    return sum(int(x) * w for x, w in zip(d, weights, strict=True)) % 11 == 0 and len(set(d)) > 1


def abn_ok(num: str) -> bool:
    d = _digits(num)
    if not d.isdigit() or len(d) != 11:
        return False
    nums = [int(x) for x in d]
    nums[0] -= 1
    weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
    return sum(n * w for n, w in zip(nums, weights, strict=True)) % 89 == 0


def medicare_ok(num: str) -> bool:
    d = _digits(num)
    if not d.isdigit() or len(d) not in (10, 11) or d[0] not in "23456":
        return False
    check = sum(int(x) * w for x, w in zip(d[:8], [1, 3, 7, 9, 1, 3, 7, 9], strict=True)) % 10
    return check == int(d[8])


def iban_ok(s: str) -> bool:
    s = re.sub(r"\s", "", s).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    moved = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1


# ------------------------------------------------------------------ detectors
@dataclass(frozen=True)
class Kind:
    name: str
    level: str          # secret | protected | normal
    label: str          # human description


KINDS = {k.name: k for k in [
    Kind("card_number", "secret", "payment card number"),
    Kind("au_tfn", "secret", "Australian tax file number"),
    Kind("au_medicare", "secret", "Medicare number"),
    Kind("bank_account", "secret", "bank account (BSB + account)"),
    Kind("iban", "secret", "IBAN"),
    Kind("api_key", "secret", "API key or token"),
    Kind("private_key", "secret", "private key"),
    Kind("password", "secret", "password or secret"),
    Kind("gov_id", "secret", "government ID (passport / licence)"),
    Kind("au_abn", "normal", "Australian Business Number (public)"),
    Kind("email", "protected", "email address"),
    Kind("phone", "protected", "phone number"),
    Kind("person_name", "protected", "person's name"),
    Kind("address", "protected", "street address"),
    Kind("dob", "protected", "date of birth"),
    Kind("ip_address", "protected", "IP address"),
    Kind("money", "protected", "financial amount"),
    Kind("free_text", "protected", "free text (may contain anything)"),
    Kind("identifier", "normal", "record identifier"),
    Kind("category", "normal", "status / category / type"),
    Kind("timestamp", "normal", "date or time"),
]}

VALUE_PATTERNS: list[tuple[str, re.Pattern[str], Any]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), None),
    ("api_key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|"
                           r"gh[pousr]_[A-Za-z0-9]{30,}|xox[abpr]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|"
                           r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), None),
    ("card_number", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), luhn_ok),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){10,30}\b"), iban_ok),
    ("bank_account", re.compile(r"\b\d{3}-?\d{3}[ ,/]+\d{6,10}\b"), None),
    ("au_medicare", re.compile(r"\b[2-6]\d{3} ?\d{5} ?\d{1,2}\b"), medicare_ok),
    ("au_abn", re.compile(r"\b\d{2} ?\d{3} ?\d{3} ?\d{3}\b"), abn_ok),
    ("au_tfn", re.compile(r"\b\d{3} ?\d{3} ?\d{2,3}\b"), tfn_ok),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), None),
    ("phone", re.compile(r"(?:\+\d{1,3}[ -]?)?\(?0?[2-478]\)?[ -]?\d{2,4}[ -]?\d{3}[ -]?\d{3}\b"), None),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), None),
]

NAME_HINTS: list[tuple[str, str]] = [
    (r"(^|_)(cvv|cvc|pan|card(_?num(ber)?)?|cc_?num)($|_)", "card_number"),
    (r"(^|_)tfn($|_)|tax_?file", "au_tfn"),
    (r"medicare", "au_medicare"),
    (r"(^|_)(bsb|account_?(no|num(ber)?)|bank_?account|acct)($|_)", "bank_account"),
    (r"iban", "iban"),
    (r"(passport|licen[cs]e|driver|national_?id|ssn|nin)", "gov_id"),
    (r"(password|passwd|secret|api_?key|token|private_?key|credential)", "password"),
    (r"(^|_)abn($|_)", "au_abn"),
    (r"e_?mail", "email"),
    (r"(phone|mobile|cell|fax|tel)($|_)", "phone"),
    (r"(^|_)(first|last|full|given|family|sur)?_?name($|_)|(^|_)(contact|customer|person)$", "person_name"),
    (r"(address|street|suburb|postcode|zip|city)", "address"),
    (r"(dob|birth)", "dob"),
    (r"(^|_)ip(_?addr(ess)?)?($|_)", "ip_address"),
    (r"(salary|income|wage|balance|credit_?limit|amount|price|total|cost)", "money"),
    (r"(note|comment|description|body|message|content|text)", "free_text"),
    (r"(^|_)(id|uuid|key|ref|number|no)$|_id$", "identifier"),
    (r"(status|type|category|plan|tier|state|kind|currency|country)$", "category"),
    (r"(_at|_on|date|time|created|updated)$", "timestamp"),
]


@dataclass
class Finding:
    kind: str
    level: str
    confidence: float           # 0..1
    reasons: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return KINDS[self.kind].label


def detect_value(value: Any) -> str | None:
    """The most sensitive kind found anywhere in one value, or None."""
    if value is None:
        return None
    text = str(value)
    for kind, pattern, check in VALUE_PATTERNS:
        for m in pattern.finditer(text):
            if check is None or check(m.group(0)):
                return kind
    return None


def scan_text(text: str) -> list[tuple[str, int, int]]:
    """All sensitive spans in free text: (kind, start, end). Overlaps keep the first (most sensitive)."""
    spans: list[tuple[str, int, int]] = []
    for kind, pattern, check in VALUE_PATTERNS:
        for m in pattern.finditer(text):
            if check is not None and not check(m.group(0)):
                continue
            if any(s < m.end() and m.start() < e for _, s, e in spans):
                continue
            spans.append((kind, m.start(), m.end()))
    return sorted(spans, key=lambda s: s[1])


def redact(text: str) -> str:
    out, last = [], 0
    for kind, s, e in scan_text(text):
        out += [text[last:s], f"[{kind.upper()}]"]
        last = e
    return "".join(out + [text[last:]])


_RANK = {"secret": 3, "protected": 2, "normal": 1}


def classify_column(name: str, samples: list[Any]) -> Finding:
    """Label a column from its name and sample values. Picks the most sensitive credible signal."""
    lname = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    name_kind = next((k for pat, k in NAME_HINTS if re.search(pat, lname)), None)

    values = [v for v in samples if v not in (None, "")]
    value_kinds = Counter(k for k in (detect_value(v) for v in values) if k)
    top_kind, top_n = value_kinds.most_common(1)[0] if value_kinds else (None, 0)
    ratio = top_n / len(values) if values else 0.0

    candidates: list[Finding] = []
    if name_kind == "free_text" and top_kind:
        # a notes/description column that sometimes holds sensitive data: free text at that level
        lvl = max(KINDS[top_kind].level, "protected", key=lambda x: _RANK[x])
        return Finding("free_text", lvl, 0.8, [f"column name '{name}' suggests free text",
                                               f"{top_n}/{len(values)} values contain: {KINDS[top_kind].label}"])
    if top_kind and ratio > 0.6:
        candidates.append(Finding(top_kind, KINDS[top_kind].level, round(min(1.0, 0.5 + ratio / 2), 2),
                                  [f"{top_n}/{len(values)} sample values match: {KINDS[top_kind].label}"]))
    elif top_kind:
        # some values contain sensitive data: treat the column as free text holding it
        lvl = KINDS[top_kind].level
        candidates.append(Finding("free_text", lvl, 0.6,
                                  [f"{top_n}/{len(values)} values contain: {KINDS[top_kind].label}"]))
    if name_kind:
        candidates.append(Finding(name_kind, KINDS[name_kind].level, 0.6 if values else 0.5,
                                  [f"column name '{name}' suggests: {KINDS[name_kind].label}"]))
    if not candidates:
        long_text = values and sum(len(str(v)) > 60 for v in values) / len(values) > 0.3
        if long_text:
            return Finding("free_text", "protected", 0.5, ["long free text; could contain anything"])
        return Finding("category", "protected", 0.3, ["no signal found; defaulting to protected to be safe"])

    best = max(candidates, key=lambda f: (_RANK[f.level], f.confidence))
    agree = [c for c in candidates if c.kind == best.kind]
    if len(agree) > 1:
        best = Finding(best.kind, best.level, min(1.0, best.confidence + 0.2),
                       [r for c in agree for r in c.reasons])
    else:
        best.reasons = [r for c in candidates for r in c.reasons]
    return best


DOC_MARKERS = re.compile(r"\b(confidential|internal[ -]only|do not (?:distribute|share)|restricted|"
                         r"commercial[ -]in[ -]confidence|privileged)\b", re.I)


def classify_document(name: str, text: str) -> Finding:
    """Label a whole document: secrets inside -> secret; marked internal -> protected; else normal."""
    kinds = {k for k, _, _ in scan_text(text)}
    secrets = sorted(k for k in kinds if KINDS[k].level == "secret")
    if secrets:
        return Finding("free_text", "secret", 0.8, [f"contains {', '.join(KINDS[k].label for k in secrets)}"])
    if m := DOC_MARKERS.search(text[:4000]):
        return Finding("free_text", "protected", 0.8, [f"marked '{m.group(0)}'"])
    personal = sorted(k for k in kinds if KINDS[k].level == "protected")
    if personal:
        return Finding("free_text", "protected", 0.6, [f"contains {', '.join(KINDS[k].label for k in personal)}"])
    return Finding("free_text", "normal", 0.5, ["no sensitive markers or data found; review before sharing"])
