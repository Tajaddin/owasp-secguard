"""Injection detectors for the OWASP Top 10 input-validation categories.

Rule-based and dependency-free: each detector is a set of compiled patterns
tuned to fire on attack payloads while staying quiet on ordinary text. The
goal is high recall on a labeled attack corpus with a low false-positive rate
on benign input (both measured in benchmarks/detection_bench.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import unquote_plus


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Category(str, Enum):
    SQLI = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"


@dataclass(frozen=True)
class Detection:
    category: Category
    severity: Severity
    pattern: str
    matched: str


# Each entry: (compiled regex, severity, label). Patterns operate on the
# URL-decoded value so percent-encoded payloads are caught.
_SQLI = [
    (re.compile(r"\bunion\b[\s/*]+\bselect\b", re.I), Severity.HIGH, "union-select"),
    (re.compile(r"\bor\b\s+\d+\s*=\s*\d+", re.I), Severity.HIGH, "or-1=1"),
    (re.compile(r"'\s*(or|and)\s+'?\d|'\s*or\s+'[^']*'\s*=\s*'", re.I), Severity.HIGH, "quote-or"),
    (re.compile(r"'\s*(--|#)", re.I), Severity.HIGH, "quote-comment"),
    (re.compile(r";\s*(drop|delete|update|insert)\s+", re.I), Severity.HIGH, "stacked-query"),
    (re.compile(r"\b(sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b", re.I), Severity.MEDIUM, "time-based"),
    (re.compile(r"--\s|#\s*$|/\*.*\*/", re.I), Severity.LOW, "sql-comment"),
]

_XSS = [
    (re.compile(r"<script[\s>]", re.I), Severity.HIGH, "script-tag"),
    (re.compile(r"javascript:\s*\S", re.I), Severity.HIGH, "javascript-uri"),
    (re.compile(r"on(error|load|click|mouseover)\s*=", re.I), Severity.HIGH, "event-handler"),
    (re.compile(r"<img[^>]+\bsrc\s*=\s*[\"']?\s*x", re.I), Severity.MEDIUM, "img-onerror"),
    (re.compile(r"<(iframe|svg|body)[\s>]", re.I), Severity.MEDIUM, "dangerous-tag"),
    (re.compile(r"document\.(cookie|location)|window\.location", re.I), Severity.MEDIUM, "dom-sink"),
]

_PATH = [
    (re.compile(r"(\.\./|\.\.\\){2,}"), Severity.HIGH, "dot-dot-sequence"),
    (re.compile(r"/etc/(passwd|shadow|hosts)\b", re.I), Severity.HIGH, "etc-passwd"),
    (re.compile(r"\bc:\\windows\\|\\system32\\", re.I), Severity.HIGH, "windows-system"),
    (re.compile(r"(\.\./|\.\.\\)"), Severity.LOW, "single-dotdot"),
]

_CMDI = [
    (re.compile(r"[;|&]{1,2}\s*(cat|ls|whoami|id|curl|wget|nc|bash|sh|powershell)\b", re.I), Severity.HIGH, "chained-cmd"),
    (re.compile(r"\$\(.*\)|`[^`]+`"), Severity.HIGH, "command-substitution"),
    (re.compile(r"\|\s*(nc|netcat|bash|sh)\b", re.I), Severity.HIGH, "pipe-to-shell"),
    (re.compile(r"\b(rm\s+-rf|chmod\s+777)\b", re.I), Severity.MEDIUM, "destructive-cmd"),
]

_RULES = {
    Category.SQLI: _SQLI,
    Category.XSS: _XSS,
    Category.PATH_TRAVERSAL: _PATH,
    Category.COMMAND_INJECTION: _CMDI,
}


def scan_value(value: str) -> list[Detection]:
    """Return all detections for a single string value (URL-decoded first)."""
    if not value:
        return []
    decoded = unquote_plus(value)
    candidates = {value, decoded}
    out: list[Detection] = []
    seen: set[tuple[Category, str]] = set()
    for text in candidates:
        for category, rules in _RULES.items():
            for regex, severity, label in rules:
                m = regex.search(text)
                if m and (category, label) not in seen:
                    seen.add((category, label))
                    out.append(Detection(category=category, severity=severity, pattern=label, matched=m.group(0)[:80]))
    return out


def is_malicious(value: str, min_severity: Severity = Severity.MEDIUM) -> bool:
    """True if any detection at or above min_severity fires."""
    order = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}
    threshold = order[min_severity]
    return any(order[d.severity] >= threshold for d in scan_value(value))
