from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

_REWRITE_LISTS = {
    "https://rewrite.test/a.list": """
# Comment.
hostname = a.test, *.b.test, -c.test
^https?://a\\.test/ad url reject
^https?://a\\.test/\\?q=1 url 302 https://a.test/
""",
    "https://rewrite.test/b.list": """
; Another comment.
hostname=b.test, a.test
^https?://b\\.test/ad url reject-200
""",
}


@pytest.fixture(autouse=True)
def _fake_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "conf_gen.generator.quantumult_generator.fetch_url",
        lambda url: SimpleNamespace(text=_REWRITE_LISTS[url]),
    )


def _rewrites_info() -> list[dict[str, str]]:
    return [
        {"name": "A", "url": "https://rewrite.test/a.list"},
        {"name": "B", "url": "https://rewrite.test/b.list"},
    ]


def _sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: list[str] = []
    for line in text.splitlines():
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], [])
        elif line:
            current.append(line)
    return sections


def test_parse_rewrites_splits_hostnames_from_rewrites() -> None:
    from conf_gen.generator.quantumult_generator import QuantumultGenerator

    rewrites, hostnames = QuantumultGenerator.parse_rewrites(_rewrites_info())

    assert rewrites == [
        "# A",
        "^https?://a\\.test/ad url reject",
        "^https?://a\\.test/\\?q=1 url 302 https://a.test/",
        "# B",
        "^https?://b\\.test/ad url reject-200",
    ]
    assert hostnames == ["a.test", "*.b.test", "-c.test", "b.test"]


def test_generate_merges_rewrite_hostnames_into_mitm(tmp_path: Path) -> None:
    from conf_gen.generator.quantumult_generator import QuantumultGenerator

    path = tmp_path / "quantumult.conf"
    QuantumultGenerator(
        src_file="source.yaml",
        proxies=[],
        per_region_proxies=[],
        proxy_groups=[],
        mitm={"passphrase": "", "p12": "", "hostname": ["user.test", "b.test"]},
        rewrites=_rewrites_info(),
    ).generate(str(path))

    sections = _sections(path.read_text(encoding="utf-8"))
    assert "rewrites" not in sections
    assert sections["mitm"] == [
        "passphrase=",
        "p12=",
        "hostname=user.test,b.test,a.test,*.b.test,-c.test",
    ]
    assert sections["rewrite_local"][0] == "# A"
    assert len(sections["rewrite_local"]) == 5


def test_generate_without_rewrites_keeps_mitm_untouched(tmp_path: Path) -> None:
    from conf_gen.generator.quantumult_generator import QuantumultGenerator

    path = tmp_path / "quantumult.conf"
    QuantumultGenerator(
        src_file="source.yaml",
        proxies=[],
        per_region_proxies=[],
        proxy_groups=[],
    ).generate(str(path))

    sections = _sections(path.read_text(encoding="utf-8"))
    assert sections["mitm"] == []
    assert sections["rewrite_local"] == []


def test_generated_sections_are_not_configurable() -> None:
    from conf_gen.generator.quantumult_generator import QuantumultGenerator

    with pytest.raises(ValueError, match="rewrite_local"):
        QuantumultGenerator(
            src_file="source.yaml",
            proxies=[],
            per_region_proxies=[],
            proxy_groups=[],
            rewrite_local={"a": "b"},
        )
