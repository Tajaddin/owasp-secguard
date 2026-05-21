"""Measure detector precision/recall over the labeled corpus.

Reports recall on MALICIOUS payloads and the false-positive rate on BENIGN
inputs, plus precision and F1. No infra, runs in well under a second.

    python -m benchmarks.detection_bench
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from secguard.corpus import BENIGN, MALICIOUS
from secguard.detectors import Severity, is_malicious

RESULTS = Path(__file__).parent / "results" / "detection.json"


def main() -> int:
    min_sev = Severity.MEDIUM

    tp = sum(1 for p in MALICIOUS if is_malicious(p, min_sev))   # caught attacks
    fn = len(MALICIOUS) - tp                                      # missed attacks
    fp = sum(1 for p in BENIGN if is_malicious(p, min_sev))       # benign flagged
    tn = len(BENIGN) - fp

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    summary = {
        "min_severity": min_sev.value,
        "malicious_samples": len(MALICIOUS),
        "benign_samples": len(BENIGN),
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "recall_pct": round(recall * 100, 2),
        "precision_pct": round(precision * 100, 2),
        "false_positive_rate_pct": round(fpr * 100, 2),
        "f1": round(f1, 4),
    }
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    if fn:
        print("\nMissed payloads:", file=sys.stderr)
        for p in MALICIOUS:
            if not is_malicious(p, min_sev):
                print(f"  FN: {p!r}", file=sys.stderr)
    if fp:
        print("\nFalse positives:", file=sys.stderr)
        for p in BENIGN:
            if is_malicious(p, min_sev):
                print(f"  FP: {p!r}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
