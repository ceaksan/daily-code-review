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


class TestReconHash:
    def test_changes_when_file_hash_changes(self):
        cat = [{"id": "sqli", "title": "T", "prompt": "sec-sqli.md", "enabled": True}]
        inv1 = [{"path": "a.py", "content_hash": "h1", "size": 1}]
        inv2 = [{"path": "a.py", "content_hash": "h2", "size": 1}]
        assert security.compute_recon_hash(
            inv1, cat, "p"
        ) != security.compute_recon_hash(inv2, cat, "p")

    def test_changes_when_catalog_changes(self):
        inv = [{"path": "a.py", "content_hash": "h1", "size": 1}]
        c1 = [{"id": "sqli", "title": "T", "prompt": "sec-sqli.md", "enabled": True}]
        c2 = [{"id": "xss", "title": "T", "prompt": "sec-xss.md", "enabled": True}]
        assert security.compute_recon_hash(inv, c1, "p") != security.compute_recon_hash(
            inv, c2, "p"
        )

    def test_stable_when_nothing_changes(self):
        inv = [{"path": "a.py", "content_hash": "h1", "size": 1}]
        c = [{"id": "sqli", "title": "T", "prompt": "sec-sqli.md", "enabled": True}]
        assert security.compute_recon_hash(inv, c, "p") == security.compute_recon_hash(
            inv, c, "p"
        )


class TestGuardedRead:
    def test_reads_valid_inventory_path(self, tmp_path):
        (tmp_path / "a.py").write_text("hello")
        out = security.guarded_read(tmp_path.resolve(), "a.py", {"a.py"})
        assert out == "hello"

    def test_rejects_traversal(self, tmp_path):
        assert security.guarded_read(tmp_path.resolve(), "../x", {"../x"}) is None

    def test_rejects_not_in_inventory(self, tmp_path):
        (tmp_path / "a.py").write_text("hi")
        assert security.guarded_read(tmp_path.resolve(), "a.py", set()) is None


class TestChunkFiles:
    def test_splits_by_budget(self, tmp_path):
        (tmp_path / "a.py").write_text("a" * 60)
        (tmp_path / "b.py").write_text("b" * 60)
        inv = {"a.py", "b.py"}
        batches, ns = security.chunk_files(
            tmp_path.resolve(), ["a.py", "b.py"], inv, budget=100
        )
        assert len(batches) == 2  # each 60 chars, budget 100 -> separate batches

    def test_oversized_single_file_chunked_not_dropped(self, tmp_path):
        (tmp_path / "big.py").write_text("\n".join(f"line{i}" for i in range(400)))
        batches, ns = security.chunk_files(
            tmp_path.resolve(), ["big.py"], {"big.py"}, budget=200
        )
        assert len(batches) >= 2
        assert ns == []

    def test_unreadable_path_to_not_scanned(self, tmp_path):
        batches, ns = security.chunk_files(
            tmp_path.resolve(), ["ghost.py"], {"ghost.py"}, budget=100
        )
        assert any(n["reason"] in ("unreadable", "invalid") for n in ns)


import json
from dnm_audit.db import HealthDB


class TestValidateReconOutput:
    def test_drops_unknown_class_and_bad_path(self):
        raw = {"sqli": ["a.py", "../evil"], "unknownclass": ["a.py"]}
        out = security.validate_recon_output(raw, {"sqli", "xss"}, {"a.py"})
        assert out == {"sqli": ["a.py"]}


class TestRunRecon:
    def _repo(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("import sqlite3")
        return dict(name="r", path=str(tmp_path), source_dirs=["src/"], ignore_dirs=[])

    def test_cache_miss_calls_claude_then_hit_does_not(self, tmp_path):
        from types import SimpleNamespace

        cfg = SimpleNamespace(
            SECURITY_CATALOG=[
                {"id": "sqli", "title": "T", "prompt": "sec-sqli.md", "enabled": True},
            ]
        )
        repo = self._repo(tmp_path)
        db = HealthDB(tmp_path / "s.db")
        inv, ns = security.build_inventory(repo, cfg)
        calls = []

        def fake_claude(prompt):
            calls.append(prompt)
            return json.dumps({"sqli": ["src/app.py"]})

        out1 = security.run_recon(
            repo, cfg, db, inv, ns, claude=fake_claude, quiet=True
        )
        assert out1 == {"sqli": ["src/app.py"]}
        assert len(calls) == 1
        out2 = security.run_recon(
            repo, cfg, db, inv, ns, claude=fake_claude, quiet=True
        )
        assert out2 == {"sqli": ["src/app.py"]}
        assert len(calls) == 1  # cache hit, no second call

    def test_cache_invalidates_on_file_change(self, tmp_path):
        from types import SimpleNamespace

        cfg = SimpleNamespace(
            SECURITY_CATALOG=[
                {"id": "sqli", "title": "T", "prompt": "sec-sqli.md", "enabled": True},
            ]
        )
        repo = self._repo(tmp_path)
        db = HealthDB(tmp_path / "s.db")
        calls = []

        def fake_claude(prompt):
            calls.append(prompt)
            return json.dumps({"sqli": ["src/app.py"]})

        inv, ns = security.build_inventory(repo, cfg)
        security.run_recon(repo, cfg, db, inv, ns, claude=fake_claude, quiet=True)
        (tmp_path / "src" / "app.py").write_text("import os  # changed")
        inv2, ns2 = security.build_inventory(repo, cfg)
        security.run_recon(repo, cfg, db, inv2, ns2, claude=fake_claude, quiet=True)
        assert len(calls) == 2


class TestDedup:
    def test_exact_and_coarse(self):
        f = lambda **k: {
            "file": "a.py",
            "line": 5,
            "category": "sqli",
            "severity": "info",
            **k,
        }
        findings = [
            f(title="X"),
            f(title="X"),  # exact dup
            f(title="X reworded", severity="critical"),  # coarse dup, higher sev
        ]
        out = security.dedup_findings(findings)
        assert len(out) == 1
        assert out[0]["severity"] == "critical"


class TestSelectForVerify:
    def _f(self, cat, sev, line):
        return {
            "file": "a.py",
            "line": line,
            "category": cat,
            "severity": sev,
            "title": f"{cat}{line}",
        }

    def test_min_quota_guaranteed_over_total(self):
        by_class = {
            c: [self._f(c, "info", i) for i in range(5)] for c in ("a", "b", "c")
        }
        to_verify, capped = security.select_for_verify(
            by_class, max_per_class=30, max_total=2, min_per_class=2
        )
        # 3 classes * 2 min = 6 verified even though max_total=2
        assert len(to_verify) == 6
        assert len(capped) == 9

    def test_fewer_than_quota_all_verified(self):
        by_class = {"a": [self._f("a", "info", 1)]}
        to_verify, capped = security.select_for_verify(
            by_class, max_per_class=30, max_total=10, min_per_class=3
        )
        assert len(to_verify) == 1
        assert capped == []


class TestRunVerify:
    def _finding(self):
        return {
            "file": "a.py",
            "line": 3,
            "category": "sqli",
            "severity": "warning",
            "title": "SQLi",
        }

    def test_confirmed_sets_confidence_and_severity(self, tmp_path):
        (tmp_path / "a.py").write_text("q = 'SELECT ' + x")
        repo = dict(name="r", path=str(tmp_path))

        def claude(prompt):
            return json.dumps(
                {
                    "verdict": "confirmed",
                    "confidence": 0.9,
                    "severity": "critical",
                    "exploit_path": "inject x",
                    "reason": "ok",
                }
            )

        out = security.run_verify(
            repo, self._finding(), "profile", {"a.py"}, claude=claude
        )
        assert out["verification"] == "confirmed"
        assert out["confidence"] == 0.9
        assert out["verify_severity"] == "critical"

    def test_refuted(self, tmp_path):
        (tmp_path / "a.py").write_text("q = 1")
        repo = dict(name="r", path=str(tmp_path))

        def claude(prompt):
            return json.dumps(
                {
                    "verdict": "refuted",
                    "confidence": 0.8,
                    "severity": "info",
                    "exploit_path": "",
                    "reason": "parametrized",
                }
            )

        out = security.run_verify(repo, self._finding(), "p", {"a.py"}, claude=claude)
        assert out["verification"] == "refuted"

    def test_malformed_is_fail_open(self, tmp_path):
        (tmp_path / "a.py").write_text("q = 1")
        repo = dict(name="r", path=str(tmp_path))

        def claude(prompt):
            return "garbage not json"

        out = security.run_verify(repo, self._finding(), "p", {"a.py"}, claude=claude)
        assert out["verification"] == "failed"
        assert out["confidence"] is None

    def test_partition(self):
        active, refuted = security.partition_verified(
            [
                {"verification": "confirmed"},
                {"verification": "failed"},
                {"verification": "refuted"},
            ]
        )
        assert len(active) == 2 and len(refuted) == 1


from dnm_audit import reporter


class TestSecurityReport:
    def test_redacts_secret_value(self):
        out = reporter.redact_secrets("token = AKIA1234567890ABCDEFGHIJKLMNOP")
        assert "AKIA1234567890ABCDEFGHIJKLMNOP" not in out
        assert "REDACTED" in out

    def test_final_severity_prefers_verify(self):
        assert (
            reporter.final_severity({"severity": "info", "verify_severity": "critical"})
            == "critical"
        )
        assert reporter.final_severity({"severity": "warning"}) == "warning"

    def test_report_has_all_sections(self):
        active = [
            {
                "file": "a.py",
                "line": 1,
                "category": "sqli",
                "title": "SQLi",
                "detail": "d",
                "suggestion": "fix",
                "severity": "critical",
                "verify_severity": "critical",
                "verification": "confirmed",
                "confidence": 0.9,
                "exploit_path": "x",
            }
        ]
        capped = [
            {
                "file": "b.py",
                "line": 2,
                "category": "xss",
                "title": "XSS",
                "detail": "d",
                "severity": "info",
            }
        ]
        refuted = [
            {
                "file": "c.py",
                "line": 3,
                "category": "jwt",
                "title": "JWT",
                "detail": "d",
                "reason": "not exploitable",
                "verification": "refuted",
            }
        ]
        not_scanned = [{"path": "big.bin", "reason": "unreadable"}]
        trunc = {"total_capped": 1, "per_class": {"xss": 1}}
        md = reporter.generate_security_report(
            "myrepo", active, capped, refuted, not_scanned, trunc
        )
        assert "P0" in md
        assert "Capped (unverified)" in md
        assert "Refuted" in md
        assert "Not scanned" in md
        assert "Truncation" in md or "capped" in md.lower()
