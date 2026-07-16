import os
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


class TestMatching:
    def test_suffix_match(self):
        assert security.matches_security_file("a.py", {".py"}, [])

    def test_pattern_match_dotenv(self):
        assert security.matches_security_file(".env.local", set(), [".env*"])

    def test_pattern_match_dockerfile(self):
        assert security.matches_security_file("Dockerfile", set(), ["Dockerfile*"])

    def test_no_match(self):
        assert not security.matches_security_file("readme.md", {".py"}, ["Dockerfile*"])


def _repo(tmp_path, **over):
    cfg = dict(source_dirs=["src/"], ignore_dirs=["node_modules/"], path=str(tmp_path))
    cfg.update(over)
    return cfg


class TestBuildInventory:
    def test_includes_src_and_root_and_github(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x=1")
        (tmp_path / ".env").write_text("SECRET=abc")  # root-level
        (tmp_path / "Dockerfile").write_text("FROM python")  # root, pattern
        gh = tmp_path / ".github" / "workflows"
        gh.mkdir(parents=True)
        (gh / "ci.yml").write_text("on: push")
        (tmp_path / "readme.md").write_text("nope")  # excluded

        inv, not_scanned = security.build_inventory(_repo(tmp_path), SimpleNamespace())
        paths = {e["path"] for e in inv}
        assert "src/app.py" in paths
        assert ".env" in paths
        assert "Dockerfile" in paths
        assert ".github/workflows/ci.yml" in paths
        assert "readme.md" not in paths
        assert all(len(e["content_hash"]) == 64 for e in inv)

    def test_ignore_dirs_respected(self, tmp_path):
        (tmp_path / "src" / "node_modules").mkdir(parents=True)
        (tmp_path / "src" / "node_modules" / "x.js").write_text("y")
        (tmp_path / "src" / "app.js").write_text("z")
        inv, _ = security.build_inventory(_repo(tmp_path), SimpleNamespace())
        paths = {e["path"] for e in inv}
        assert "src/app.js" in paths
        assert "src/node_modules/x.js" not in paths

    def test_ignore_dirs_glob_respected(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x=1")
        (tmp_path / "src" / "app.test.py").write_text("y=2")
        inv, _ = security.build_inventory(
            _repo(tmp_path, ignore_dirs=["*.test.py"]), SimpleNamespace()
        )
        paths = {e["path"] for e in inv}
        assert "src/app.py" in paths
        assert "src/app.test.py" not in paths

    def test_symlink_escape_skipped(self, tmp_path):
        outside = tmp_path.parent / "outside_secret.env"
        outside.write_text("SECRET=1")
        (tmp_path / "src").mkdir()
        link = tmp_path / "src" / "link.env"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError):
            import pytest

            pytest.skip("symlinks unsupported")
        inv, not_scanned = security.build_inventory(_repo(tmp_path), SimpleNamespace())
        paths = {e["path"] for e in inv}
        assert "src/link.env" not in paths
        assert any(n["reason"] == "symlink-escape" for n in not_scanned)
