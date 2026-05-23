# SYNTHETIC SCANNER FIXTURES — NOT REAL CREDENTIALS
# These patterns exist to test the secret-detection rules in this repo.
# If your scanner flagged these, allowlist this file.

from secguard.scanner import scan_text, scan_text_has_secret, shannon_entropy


class TestSecretPatterns:
    def test_detects_anthropic_key(self):
        f = scan_text("ANTHROPIC_API_KEY=sk-ant-api03-" + "A1b2C3d4" * 6)
        assert any(x.rule == "anthropic_api_key" for x in f)

    def test_detects_aws_access_key(self):
        f = scan_text("aws_key = AKIAAAAAAAAAAAAAAAAA")  # fixture: synthetic, never real
        assert any(x.rule == "aws_access_key_id" for x in f)

    def test_detects_private_key(self):
        f = scan_text("-----BEGIN RSA PRIVATE KEY-----")  # fixture: synthetic, never real
        assert any(x.rule == "private_key" for x in f)

    def test_detects_db_url_with_password(self):
        f = scan_text("DATABASE_URL=postgresql://user:s3cr3tP%40ss@db.host:5432/app")  # fixture: synthetic, never real
        assert any(x.rule == "db_url_with_password" for x in f)

    def test_detects_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "a" * 20 + "." + "b" * 20
        assert scan_text_has_secret(jwt)

    def test_redacts_the_value(self):
        f = scan_text("ANTHROPIC_API_KEY=sk-ant-api03-" + "Z9y8X7w6" * 6)
        assert f
        assert "sk-ant-api03-Z9y8X7w6" not in f[0].redacted
        assert f[0].redacted.startswith("sk-ant")


class TestFalsePositiveControls:
    def test_ignores_placeholder(self):
        assert not scan_text_has_secret('ANTHROPIC_API_KEY="your-api-key-here"')

    def test_ignores_empty_password(self):
        assert not scan_text_has_secret('password = ""')

    def test_ignores_localhost_db_url(self):
        assert not scan_text_has_secret("DATABASE_URL=postgresql://docqa:docqa@localhost:5432/docqa")

    def test_low_entropy_generic_not_flagged(self):
        # repetitive, low-entropy quoted value should not trip the generic rule
        assert not scan_text_has_secret('token = "aaaaaaaaaaaa"')

    def test_high_entropy_generic_flagged(self):
        assert scan_text_has_secret('token = "f3Kd9Lm2Qp7Xz1Rb8Wn"')  # fixture: synthetic, never real


class TestEntropy:
    def test_entropy_of_uniform_string(self):
        # 4 distinct symbols, equal freq -> 2 bits/char
        assert abs(shannon_entropy("abcdabcdabcd") - 2.0) < 1e-9

    def test_entropy_of_single_char(self):
        assert shannon_entropy("aaaa") == 0.0
