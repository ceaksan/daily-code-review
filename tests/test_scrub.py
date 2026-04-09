"""Tests for tools/scrub_dataset.py"""

import json
import sys
from collections import Counter
from pathlib import Path

import pytest

# Add tools/ to path so we can import scrub_dataset
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

from scrub_dataset import anonymize_file_path, scrub_record, scrub_text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_record(**overrides) -> dict:
    """Build a minimal JSONL record with sensible defaults."""
    base = {
        "id": "abc123def456",
        "ts": "2026-04-09T10:00:00+00:00",
        "session_id": "00000000-0000-0000-0000-000000000000",
        "project": "test-project",
        "tool_name": "Edit",
        "file_path": "/Users/testuser/Documents/DNM_Projects/test-project/src/app.py",
        "file_type": "py",
        "instruction": "",
        "input": "",
        "output": "",
        "change_lines": 1,
        "truncated": False,
        "status": "pending",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# AWS Key Tests
# ---------------------------------------------------------------------------


class TestAWSKeys:
    def test_aws_access_key_redacted(self):
        code = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED:aws_access_key]" in result
        assert counts["aws_access_key"] == 1

    def test_aws_secret_key_redacted(self):
        code = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result
        assert "[REDACTED:aws_secret_key]" in result
        assert counts["aws_secret_key"] == 1


# ---------------------------------------------------------------------------
# Database URL Tests
# ---------------------------------------------------------------------------


class TestDatabaseURLs:
    def test_postgresql_url_redacted(self):
        code = 'DATABASES = {"default": {"ENGINE": "django.db.backends.postgresql", "URL": "postgresql://user:pass@db.example.com:5432/mydb"}}'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "postgresql://user:pass@db.example.com" not in result
        assert "[REDACTED:database_url]" in result
        assert counts["database_url"] == 1

    def test_redis_url_redacted(self):
        code = 'REDIS_URL = "redis://default:secretpass@redis.internal:6379/0"'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "redis://default:secretpass" not in result
        assert "[REDACTED:database_url]" in result

    def test_mongodb_url_redacted(self):
        code = 'MONGO = "mongodb://admin:pwd@mongo.host:27017/prod"'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "mongodb://admin:pwd" not in result
        assert "[REDACTED:database_url]" in result


# ---------------------------------------------------------------------------
# Bearer Token Tests
# ---------------------------------------------------------------------------


class TestBearerTokens:
    def test_bearer_token_in_fetch(self):
        code = """fetch("https://api.example.com/data", {headers: {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature"}})"""
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        # Should match as JWT (more specific) or bearer
        assert "[REDACTED:" in result

    def test_bearer_simple(self):
        code = "Authorization: Bearer sk_live_abc123def456ghi789jkl012mno"
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "sk_live_abc123def456ghi789jkl012mno" not in result
        assert "[REDACTED:bearer_token]" in result


# ---------------------------------------------------------------------------
# Email Tests
# ---------------------------------------------------------------------------


class TestEmails:
    def test_email_in_comment(self):
        code = "# Author: john.doe@example.com - last updated 2026-04-01"
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "john.doe@example.com" not in result
        assert "[REDACTED:email]" in result
        assert counts["email"] == 1

    def test_multiple_emails(self):
        code = "ADMINS = ['alice@company.org', 'bob@company.org']"
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "alice@company.org" not in result
        assert "bob@company.org" not in result
        assert counts["email"] == 2


# ---------------------------------------------------------------------------
# Shopify Token Tests
# ---------------------------------------------------------------------------


class TestShopifyTokens:
    def test_shpat_token(self):
        code = 'const token = "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";'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "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" not in result
        assert "[REDACTED:shopify_token]" in result

    def test_shpss_token(self):
        code = 'SHOPIFY_SECRET = "shpss_aabbccddee11223344556677"'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "shpss_aabbccddee11223344556677" not in result
        assert "[REDACTED:shopify_token]" in result


# ---------------------------------------------------------------------------
# Internal Domain Tests
# ---------------------------------------------------------------------------


class TestInternalDomains:
    def test_internal_domains_redacted(self):
        code = 'const API_URL = "https://api.dnomia.app/v1/scout";'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "dnomia.app" not in result
        assert "[REDACTED:internal_domain]" in result

    def test_ceaksan_domain(self):
        code = "Visit https://ceaksan.com/blog for more"
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "ceaksan.com" not in result
        assert "[REDACTED:internal_domain]" in result

    def test_leetty_domain(self):
        code = 'BASE_URL = "https://leetty.com"'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "leetty.com" not in result


# ---------------------------------------------------------------------------
# Private IP Tests
# ---------------------------------------------------------------------------


class TestPrivateIPs:
    def test_192_168_redacted(self):
        code = 'ALLOWED_HOSTS = ["192.168.1.100"]'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "192.168.1.100" not in result
        assert "[REDACTED:private_ip]" in result

    def test_10_network_redacted(self):
        code = "proxy_pass http://10.0.0.5:8080;"
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "10.0.0.5" not in result
        assert "[REDACTED:private_ip]" in result


# ---------------------------------------------------------------------------
# JWT Tests
# ---------------------------------------------------------------------------


class TestJWT:
    def test_jwt_redacted(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        code = f'const jwt = "{token}";'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "[REDACTED:jwt_token]" in result


# ---------------------------------------------------------------------------
# SSH Key Tests
# ---------------------------------------------------------------------------


class TestSSHKeys:
    def test_ssh_key_header_redacted(self):
        code = "-----BEGIN RSA PRIVATE KEY-----"
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "BEGIN RSA PRIVATE KEY" not in result
        assert "[REDACTED:ssh_private_key]" in result


# ---------------------------------------------------------------------------
# Env Secret Tests
# ---------------------------------------------------------------------------


class TestEnvSecrets:
    def test_env_password(self):
        code = 'PASSWORD = "super_secret_password_123"'
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "super_secret_password_123" not in result
        assert "[REDACTED:env_secret]" in result

    def test_env_token(self):
        code = "TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        counts: Counter[str] = Counter()
        result = scrub_text(code, counts)
        assert "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" not in result
        assert "[REDACTED:env_secret]" in result


# ---------------------------------------------------------------------------
# File Path Anonymization Tests
# ---------------------------------------------------------------------------


class TestFilePathAnonymization:
    def test_strips_users_prefix(self):
        path = "/Users/testuser/Documents/DNM_Projects/daily-code-review/src/app.py"
        result = anonymize_file_path(path)
        assert result == "Documents/DNM_Projects/daily-code-review/src/app.py"
        assert "/Users/testuser/" not in result

    def test_other_user_stripped(self):
        path = "/Users/johndoe/projects/app.py"
        result = anonymize_file_path(path)
        assert result == "projects/app.py"


# ---------------------------------------------------------------------------
# Full Record Tests
# ---------------------------------------------------------------------------


class TestFullRecord:
    def test_scrub_preserves_metadata(self):
        record = make_record(
            output='DATABASES = {"URL": "postgresql://user:pass@host:5432/db"}',
        )
        counts: Counter[str] = Counter()
        scrub_record(record, counts)

        assert record["id"] == "abc123def456"
        assert record["ts"] == "2026-04-09T10:00:00+00:00"
        assert record["session_id"] == "00000000-0000-0000-0000-000000000000"
        assert record["project"] == "test-project"
        assert record["tool_name"] == "Edit"
        assert record["file_type"] == "py"
        assert record["status"] == "pending"
        assert record["change_lines"] == 1
        assert record["truncated"] is False

    def test_scrub_redacts_output(self):
        record = make_record(
            output='DATABASES = {"URL": "postgresql://user:pass@host:5432/db"}',
        )
        counts: Counter[str] = Counter()
        scrub_record(record, counts)
        assert "postgresql://" not in record["output"]
        assert "[REDACTED:database_url]" in record["output"]

    def test_scrub_redacts_instruction(self):
        record = make_record(
            instruction="update the config at ceaksan.com with the new API key",
        )
        counts: Counter[str] = Counter()
        scrub_record(record, counts)
        assert "ceaksan.com" not in record["instruction"]

    def test_file_path_anonymized(self):
        record = make_record()
        counts: Counter[str] = Counter()
        scrub_record(record, counts)
        assert "/Users/" not in record["file_path"]
        assert "src/app.py" in record["file_path"]

    def test_non_secret_content_preserved(self):
        code = """def calculate_total(items):
    return sum(item.price * item.quantity for item in items)
"""
        record = make_record(output=code)
        counts: Counter[str] = Counter()
        scrub_record(record, counts)
        assert record["output"] == code
        assert counts.total() == 0

    def test_multiple_secrets_in_one_record(self):
        code = """
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgresql://admin:secret@db.host:5432/prod"
# Contact: admin@example.com
SHOPIFY_TOKEN = "shpat_aabbccddee11223344556677"
"""
        record = make_record(output=code)
        counts: Counter[str] = Counter()
        scrub_record(record, counts)
        assert "AKIAIOSFODNN7EXAMPLE" not in record["output"]
        assert "postgresql://" not in record["output"]
        assert "admin@example.com" not in record["output"]
        assert "shpat_aabbccddee" not in record["output"]
        assert counts.total() >= 4
