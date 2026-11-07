"""Gates the hero numbers on the 45-sample corpus: full recall on its attack
payloads, zero false positives on its benign inputs."""
from secguard.corpus import BENIGN, MALICIOUS
from secguard.detectors import Severity, is_malicious


def test_recall_is_total_on_malicious_corpus():
    missed = [p for p in MALICIOUS if not is_malicious(p, Severity.MEDIUM)]
    assert missed == [], f"missed malicious payloads: {missed}"


def test_no_false_positives_on_benign_corpus():
    flagged = [p for p in BENIGN if is_malicious(p, Severity.MEDIUM)]
    assert flagged == [], f"false positives on benign inputs: {flagged}"


def test_corpus_is_substantial():
    assert len(MALICIOUS) >= 20
    assert len(BENIGN) >= 20
