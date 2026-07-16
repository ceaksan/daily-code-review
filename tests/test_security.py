import pytest
from types import SimpleNamespace

from dnm_audit import security
from dnm_audit.db import HealthDB


def _cfg(**over):
    base = dict(
        SECURITY_CATALOG=[
            {
                "id": "sqli",
                "title": "SQL Injection",
                "prompt": "sec-sqli.md",
                "enabled": True,
            },
            {"id": "xss", "title": "XSS", "prompt": "sec-xss.md", "enabled": False},
        ]
    )
    base.update(over)
    return SimpleNamespace(**base)


class TestLoadCatalog:
    def test_returns_only_enabled(self):
        entries = security.load_catalog(_cfg())
        assert [e["id"] for e in entries] == ["sqli"]

    def test_duplicate_id_raises(self):
        cfg = _cfg(
            SECURITY_CATALOG=[
                {"id": "sqli", "title": "A", "prompt": "sec-a.md", "enabled": True},
                {"id": "sqli", "title": "B", "prompt": "sec-b.md", "enabled": True},
            ]
        )
        with pytest.raises(ValueError, match="duplicate"):
            security.load_catalog(cfg)

    def test_prompt_traversal_raises(self):
        cfg = _cfg(
            SECURITY_CATALOG=[
                {"id": "x", "title": "X", "prompt": "../evil.md", "enabled": True},
            ]
        )
        with pytest.raises(ValueError, match="prompt"):
            security.load_catalog(cfg)

    def test_missing_field_raises(self):
        cfg = _cfg(SECURITY_CATALOG=[{"id": "x", "enabled": True}])
        with pytest.raises(ValueError):
            security.load_catalog(cfg)

    def test_get_setting_falls_back_to_default(self):
        cfg = SimpleNamespace()
        assert (
            security.get_setting(cfg, "SECURITY_MAX_FINDINGS_TOTAL")
            == security.SECURITY_DEFAULTS["SECURITY_MAX_FINDINGS_TOTAL"]
        )


class TestSecurityReconTable:
    def test_upsert_then_get(self, tmp_path):
        db = HealthDB(tmp_path / "s.db")
        db.upsert_security_recon("repoA", "hash1", '{"sqli": ["a.py"]}')
        row = db.get_security_recon("repoA")
        assert row["recon_hash"] == "hash1"
        assert row["profile_json"] == '{"sqli": ["a.py"]}'

    def test_single_row_per_repo(self, tmp_path):
        db = HealthDB(tmp_path / "s.db")
        db.upsert_security_recon("repoA", "hash1", "{}")
        db.upsert_security_recon("repoA", "hash2", '{"x": []}')
        row = db.get_security_recon("repoA")
        assert row["recon_hash"] == "hash2"
        cur = db._conn.execute(
            "SELECT COUNT(*) c FROM security_recon WHERE repo='repoA'"
        )
        assert cur.fetchone()["c"] == 1

    def test_get_missing_returns_none(self, tmp_path):
        db = HealthDB(tmp_path / "s.db")
        assert db.get_security_recon("nope") is None
