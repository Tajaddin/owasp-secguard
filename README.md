# owasp-secguard

> OWASP injection-detection middleware for FastAPI plus a secrets scanner. **100% recall at 0% false-positive rate (F1 = 1.0) on a 45-sample labeled corpus** of SQLi / XSS / path-traversal / command-injection attacks vs. benign inputs. Dependency-light, 37 tests.

[![ci](https://github.com/Tajaddin/owasp-secguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Tajaddin/owasp-secguard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)

## Hero metrics

Reproducible instantly with no infra:

```bash
python -m benchmarks.detection_bench
```

| Metric | Value |
|---|---:|
| Malicious payloads | 25 (SQLi, XSS, path traversal, command injection; incl. URL-encoded) |
| Benign inputs | 20 (SQL-ish prose, code, file paths, marketing copy) |
| **Recall** | **100%** |
| **Precision** | **100%** |
| **False-positive rate** | **0%** |
| **F1** | **1.0** |

The benign set is deliberately adversarial toward naive detectors: it includes "Please select your database plan", "order by date please", and "Drop me an email when you union the teams", which a careless regex would flag. The detectors use word-boundary and structural patterns (and re-scan the URL-decoded form) to separate attacks from prose.

## How to run

Prerequisites: Python 3.10+.

```bash
# install (with the FastAPI middleware extra)
pip install -e ".[dev,fastapi]"

# unit tests
pytest -q

# detection benchmark (the F1 = 1.0 hero)
python -m benchmarks.detection_bench

# CLI: scan a file or directory for committed secrets
secguard-scan path/to/file ...
secguard-scan --staged          # scan git-staged files (pre-commit usage)
```

Smoke test: `python -c "from secguard import scan_value; print(scan_value(\"1' OR '1'='1\"))"` should print one SQL-injection detection.

## Two tools

### 1. Injection-detection middleware (FastAPI / Starlette)

```python
from fastapi import FastAPI
from secguard import SecGuardMiddleware, Severity

app = FastAPI()
app.add_middleware(SecGuardMiddleware, min_severity=Severity.MEDIUM, block=True)
```

Inspects the path, query params, and request body (URL-decoded). On a detection at or above `min_severity` it returns `403` with the matched categories, or, in audit mode (`block=False`), passes the request through and records detections on request state for logging.

### 2. Secrets scanner (pre-commit / CI)

```bash
secguard-scan path/to/file ...     # scan files
secguard-scan --staged             # scan git-staged files (pre-commit)
```

Flags committed credentials: Anthropic / OpenAI / Voyage keys, AWS access keys, GitHub / Slack tokens, private keys, JWTs, and database URLs with embedded passwords. Exits non-zero so it fails a commit or CI job.

It suppresses obvious placeholders (`your-...`, `example`, `changeme`, empty values, `localhost` DB URLs) and gates the generic `secret = "..."` rule behind a Shannon-entropy check, so docs and templates do not trip it.

> Built after a real incident where API keys leaked into a tool transcript. This is the guard that catches them before `git commit`.

As a pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Tajaddin/owasp-secguard
    rev: v0.1.0
    hooks:
      - id: secguard-scan
```

## Detection categories

| Category | Example signals |
|---|---|
| SQL injection | `UNION SELECT`, `OR 1=1`, stacked `; DROP`, quote-comment `'--`, time-based `pg_sleep(` / `WAITFOR DELAY` |
| XSS | `<script>`, `javascript:` URIs, `onerror=`/`onload=` handlers, dangerous tags |
| Path traversal | `../` sequences, `/etc/passwd`, Windows `\system32\` |
| Command injection | chained `; cat`, `$(...)` / backtick substitution, pipe-to-shell |

All detectors run on both the raw and the URL-decoded value, so percent-encoded payloads (e.g. `%2e%2e%2f`) are caught.

## Testing

```bash
pip install -e ".[dev]"
pytest --cov=secguard      # 37 tests, 95% coverage
```

- **test_detectors.py**: each category detects its payloads (incl. URL-encoded); benign prose and the severity threshold are respected.
- **test_scanner.py**: each secret type detected and redacted; placeholders / empty / localhost / low-entropy values suppressed; entropy maths.
- **test_middleware.py**: FastAPI `TestClient` blocks SQLi/XSS/cmd-injection in query and body, allows benign, supports audit mode and a HIGH-only threshold.
- **test_corpus.py**: gates 100% recall and 0% false positives on the labeled corpus.

CI also dogfoods the scanner against the repo's own tracked files.

## Project layout

```
src/secguard/
  detectors.py    # SQLi / XSS / path-traversal / cmd-injection rules
  middleware.py   # Starlette/FastAPI ASGI middleware (block or audit)
  scanner.py      # secrets scanner (patterns + placeholder + entropy gating)
  corpus.py       # labeled malicious + benign payloads
  cli.py          # secguard-scan entrypoint
benchmarks/detection_bench.py   # precision/recall/F1 hero
.pre-commit-hooks.yaml          # pre-commit integration
```

## Stack

Python 3.10+, Starlette / FastAPI (middleware), node-free pure-stdlib detectors and scanner, pytest, Docker, GitHub Actions (lint + coverage gate + benchmark gate + self-scan + image).

## License

MIT
