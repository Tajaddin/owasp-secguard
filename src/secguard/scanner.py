"""Secrets scanner.

Flags committed credentials by pattern: cloud keys, provider API keys,
private keys, and connection strings with embedded passwords. Designed to run
as a pre-commit hook or in CI so a secret never reaches a remote.

(This is the tool that would have caught an Anthropic/OpenAI/Voyage key or a
Postgres URL before it was committed.)
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

# (name, compiled pattern, redact-keep-prefix-len)
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("anthropic_api_key", re.compile(r"sk-ant-[a-zA-Z0-9-]{20,}")),
    ("openai_api_key", re.compile(r"sk-(proj-)?[a-zA-Z0-9_-]{20,}")),
    ("voyage_api_key", re.compile(r"\bpa-[a-zA-Z0-9_-]{20,}")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?[A-Za-z0-9/+]{40}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("db_url_with_password", re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:/@\s\"']+:[^@/\s\"']+@")),
    ("generic_secret_assignment", re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*[\"'][^\"'\s]{12,}[\"']")),
]

# Placeholder values that should NOT be flagged (reduce false positives).
_PLACEHOLDER = re.compile(
    r"(?i)(your[-_]?|<[^>]+>|replace|changeme|change[-_]?me|example|placeholder|todo|xxx+|\.\.\.|dummy|sample|test[-_]?(only|secret|key)?|localhost|password\"?\s*[=:]\s*\"\")"
)


@dataclass(frozen=True)
class SecretFinding:
    rule: str
    line: int
    column: int
    redacted: str


def _redact(match: str) -> str:
    if len(match) <= 8:
        return match[0] + "***"
    return match[:6] + "***" + f"(len={len(match)})"


def _looks_like_placeholder(snippet: str) -> bool:
    return bool(_PLACEHOLDER.search(snippet))


def shannon_entropy(s: str) -> float:
    """Bits-per-char entropy; used to gate the generic-assignment rule so
    obviously-non-random values do not get flagged."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan_text(text: str, *, min_entropy_for_generic: float = 3.0) -> list[SecretFinding]:
    """Scan text and return findings with line/column and a redacted preview."""
    findings: list[SecretFinding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in _PATTERNS:
            for m in pattern.finditer(line):
                snippet = m.group(0)
                if _looks_like_placeholder(line):
                    continue
                # The generic rule is noisy; require the quoted value to look random.
                if rule == "generic_secret_assignment":
                    inner = re.search(r"[\"']([^\"']{12,})[\"']", snippet)
                    if inner and shannon_entropy(inner.group(1)) < min_entropy_for_generic:
                        continue
                findings.append(
                    SecretFinding(rule=rule, line=lineno, column=m.start() + 1, redacted=_redact(snippet))
                )
    return findings


def scan_text_has_secret(text: str) -> bool:
    return len(scan_text(text)) > 0
