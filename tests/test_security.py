import pytest
from types import SimpleNamespace

from dnm_audit import security


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
