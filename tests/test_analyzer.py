"""
tests/test_analyzer.py
Comprehensive test suite for the AI Code Review system.
Run: python -m pytest tests/ -v
"""

import sys
import json
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from model.train import RuleBasedAnalyzer, LABEL2ID, ID2LABEL


# ─────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────
@pytest.fixture
def analyzer():
    return RuleBasedAnalyzer()


@pytest.fixture
def dataset():
    path = Path(__file__).parent.parent / "dataset" / "code_review_dataset.json"
    with open(path) as f:
        return json.load(f)


# ─────────────────────────────────────────────
# SQL INJECTION TESTS
# ─────────────────────────────────────────────
class TestSQLInjection:

    def test_detects_string_concat(self, analyzer):
        code = """cursor.execute("SELECT * FROM users WHERE name='" + username + "'")"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC001" in ids

    def test_detects_fstring_query(self, analyzer):
        code = """db.execute(f"SELECT * FROM orders WHERE id={order_id}")"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC001" in ids

    def test_clean_parameterized_query(self, analyzer):
        code = """cursor.execute("SELECT * FROM users WHERE name=%s", (username,))"""
        findings = analyzer.analyze(code)
        sql_findings = [f for f in findings if f["rule_id"] == "SEC001"]
        assert len(sql_findings) == 0

    def test_clean_orm_query(self, analyzer):
        code = """db.query(User).filter(User.id == user_id).first()"""
        findings = analyzer.analyze(code)
        sql_findings = [f for f in findings if f["rule_id"] == "SEC001"]
        assert len(sql_findings) == 0


# ─────────────────────────────────────────────
# XSS TESTS
# ─────────────────────────────────────────────
class TestXSS:

    def test_detects_inner_html(self, analyzer):
        code = """document.getElementById('out').innerHTML = userInput;"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC002" in ids

    def test_detects_dangerous_set_inner_html(self, analyzer):
        code = """<div dangerouslySetInnerHTML={{ __html: user.bio }} />"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC002" in ids

    def test_clean_text_content(self, analyzer):
        code = """el.textContent = userInput;"""
        findings = analyzer.analyze(code)
        xss_findings = [f for f in findings if f["rule_id"] == "SEC002"]
        assert len(xss_findings) == 0


# ─────────────────────────────────────────────
# HARDCODED SECRETS TESTS
# ─────────────────────────────────────────────
class TestHardcodedSecrets:

    def test_detects_password(self, analyzer):
        code = """password = "supersecret123" """
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC003" in ids

    def test_detects_api_key(self, analyzer):
        code = """api_key = "sk-abc123def456xyz" """
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC003" in ids

    def test_detects_token(self, analyzer):
        code = """TOKEN = "ghp_AbCdEfGhIjKlMnOpQrSt" """
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC003" in ids

    def test_clean_env_var(self, analyzer):
        code = """SECRET_KEY = os.environ['SECRET_KEY']"""
        findings = analyzer.analyze(code)
        secret_findings = [f for f in findings if f["rule_id"] == "SEC003"]
        assert len(secret_findings) == 0


# ─────────────────────────────────────────────
# WEAK CRYPTO TESTS
# ─────────────────────────────────────────────
class TestWeakCrypto:

    def test_detects_md5(self, analyzer):
        code = """return hashlib.md5(password.encode()).hexdigest()"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC004" in ids

    def test_detects_sha1(self, analyzer):
        code = """digest = hashlib.sha1(data).hexdigest()"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC004" in ids

    def test_sha256_is_clean(self, analyzer):
        code = """digest = hashlib.sha256(data).hexdigest()"""
        findings = analyzer.analyze(code)
        crypto_findings = [f for f in findings if f["rule_id"] == "SEC004"]
        assert len(crypto_findings) == 0


# ─────────────────────────────────────────────
# COMMAND INJECTION TESTS
# ─────────────────────────────────────────────
class TestCommandInjection:

    def test_detects_shell_true(self, analyzer):
        code = """subprocess.run(user_cmd, shell=True)"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC005" in ids

    def test_detects_popen_shell(self, analyzer):
        code = """subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC005" in ids

    def test_clean_shell_false(self, analyzer):
        code = """subprocess.run(['ls', '-la'], shell=False, capture_output=True)"""
        findings = analyzer.analyze(code)
        cmd_findings = [f for f in findings if f["rule_id"] == "SEC005"]
        assert len(cmd_findings) == 0


# ─────────────────────────────────────────────
# INSECURE DESERIALIZATION TESTS
# ─────────────────────────────────────────────
class TestInsecureDeserialization:

    def test_detects_pickle_loads(self, analyzer):
        code = """obj = pickle.loads(user_data)"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC007" in ids

    def test_detects_pickle_load(self, analyzer):
        code = """
with open('data.pkl', 'rb') as f:
    obj = pickle.load(f)
"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SEC007" in ids


# ─────────────────────────────────────────────
# CODE SMELL TESTS
# ─────────────────────────────────────────────
class TestCodeSmells:

    def test_detects_bare_except(self, analyzer):
        code = """
try:
    result = risky()
except:
    pass
"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SM001" in ids

    def test_clean_specific_except(self, analyzer):
        code = """
try:
    result = risky()
except ValueError as e:
    logger.error(e)
"""
        findings = analyzer.analyze(code)
        bare = [f for f in findings if f["rule_id"] == "SM001"]
        assert len(bare) == 0

    def test_detects_magic_numbers(self, analyzer):
        code = """timeout = 86400"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SM002" in ids

    def test_detects_todo(self, analyzer):
        code = """# TODO: fix this later"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SM003" in ids

    def test_detects_fixme(self, analyzer):
        code = """# FIXME: broken edge case"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "SM003" in ids


# ─────────────────────────────────────────────
# STYLE TESTS
# ─────────────────────────────────────────────
class TestStyle:

    def test_detects_print(self, analyzer):
        code = """print("debug:", value)"""
        findings = analyzer.analyze(code)
        ids = [f["rule_id"] for f in findings]
        assert "ST001" in ids

    def test_clean_logging(self, analyzer):
        code = """logger.info("Processing: %s", value)"""
        findings = analyzer.analyze(code)
        style = [f for f in findings if f["rule_id"] == "ST001"]
        assert len(style) == 0


# ─────────────────────────────────────────────
# MULTI-VULNERABILITY TESTS
# ─────────────────────────────────────────────
class TestMultiVulnerability:

    def test_detects_multiple_issues(self, analyzer):
        code = (
            'secret = "mysecret123"\n'
            'db.execute("SELECT * FROM users WHERE name=\'" + user + "\'")\n'
            'subprocess.run(cmd, shell=True)\n'
            'hashlib.md5(p.encode()).hexdigest()\n'
        )
        findings = analyzer.analyze(code)
        ids = {f["rule_id"] for f in findings}
        assert "SEC001" in ids  # SQL injection
        assert "SEC003" in ids  # hardcoded secret
        assert "SEC004" in ids  # weak crypto
        assert "SEC005" in ids  # command injection

    def test_clean_code_no_findings(self, analyzer):
        code = """
import os
import bcrypt

SECRET_KEY = os.environ['SECRET_KEY']

def hash_password(pwd: str) -> bytes:
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=12))

def get_user(user_id: int):
    return db.execute("SELECT * FROM users WHERE id=%s", (user_id,)).fetchone()
"""
        findings = analyzer.analyze(code)
        # May still flag magic number if any. Filter for real issues.
        serious = [f for f in findings if f["severity"] in ("critical", "high")]
        assert len(serious) == 0


# ─────────────────────────────────────────────
# DATASET INTEGRITY TESTS
# ─────────────────────────────────────────────
class TestDataset:

    def test_dataset_loads(self, dataset):
        assert len(dataset) > 0

    def test_all_samples_have_required_fields(self, dataset):
        required = {"id", "code", "label", "category", "severity", "message"}
        for sample in dataset:
            missing = required - set(sample.keys())
            assert not missing, f"Sample {sample.get('id')} missing: {missing}"

    def test_labels_are_valid(self, dataset):
        valid_labels = set(LABEL2ID.keys())
        for sample in dataset:
            assert sample["label"] in valid_labels, (
                f"Invalid label '{sample['label']}' in {sample['id']}"
            )

    def test_severities_are_valid(self, dataset):
        valid = {"none", "low", "medium", "high", "critical"}
        for sample in dataset:
            assert sample["severity"] in valid, (
                f"Invalid severity '{sample['severity']}' in {sample['id']}"
            )

    def test_no_empty_code(self, dataset):
        for sample in dataset:
            assert sample["code"].strip(), f"Empty code in {sample['id']}"

    def test_vulnerable_samples_have_messages(self, dataset):
        for sample in dataset:
            if sample["label"] != "clean":
                assert sample["message"].strip(), (
                    f"Missing message in non-clean sample {sample['id']}"
                )

    def test_dataset_has_all_categories(self, dataset):
        labels = {s["label"] for s in dataset}
        assert "vulnerability" in labels
        assert "clean"         in labels
        assert "code_smell"    in labels or "style" in labels


# ─────────────────────────────────────────────
# SEVERITY ORDERING TEST
# ─────────────────────────────────────────────
class TestSeverityOrdering:

    def test_critical_findings_reported(self, analyzer):
        code = """password = "mypassword123"\nresult = hashlib.md5(x.encode()).hexdigest()"""
        findings = analyzer.analyze(code)
        severities = {f["severity"] for f in findings}
        assert "critical" in severities

    def test_finding_has_line_number(self, analyzer):
        code = "password = 'abc123'\nprint('done')"
        findings = analyzer.analyze(code)
        for f in findings:
            assert isinstance(f["line"], int)
            assert f["line"] >= 1

    def test_finding_has_snippet(self, analyzer):
        code = "api_key = 'sk-abc123def456'"
        findings = analyzer.analyze(code)
        for f in findings:
            assert "snippet" in f
            assert len(f["snippet"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
