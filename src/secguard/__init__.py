"""OWASP injection-detection middleware + secrets scanner."""

from secguard.detectors import Detection, Severity, scan_value
from secguard.middleware import SecGuardMiddleware
from secguard.scanner import SecretFinding, scan_text

__version__ = "0.1.0"
__all__ = [
    "Detection",
    "SecGuardMiddleware",
    "SecretFinding",
    "Severity",
    "scan_text",
    "scan_value",
]
