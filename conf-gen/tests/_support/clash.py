from __future__ import annotations

import gzip
import platform
import stat
import subprocess
import tempfile
import types
from pathlib import Path
from typing import Self

import requests


class ClashConfigChecker:
    _release_tag = "2023-09-05-gdcc8d87"
    _release_base = "https://github.com/zhongfly/Clash-premium-backup/releases"
    _arch_map = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    _download_cache: dict[str, bytes] = {}

    def __init__(self) -> None:
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self._workdir: Path | None = None
        self._clash: Path | None = None

    def __enter__(self) -> Self:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._workdir = Path(self._tmpdir.__enter__())
        self._clash = self._resolve_clash()
        self._verify_version()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        if self._tmpdir is not None:
            self._tmpdir.__exit__(exc_type, exc_val, exc_tb)
            self._tmpdir = None

    @classmethod
    def _fetch_archive(cls, url: str) -> bytes:
        if url not in cls._download_cache:
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            cls._download_cache[url] = response.content
        return cls._download_cache[url]

    def _resolve_clash(self) -> Path:
        assert self._workdir is not None
        system = platform.system().lower()
        machine = platform.machine().lower()
        arch = self._arch_map.get(machine)
        if system not in ("darwin", "linux") or arch is None:
            raise RuntimeError(f"Dreamacro Clash test is not supported on {system}/{machine}")

        archive_name = f"clash-{system}-{arch}-n{self._release_tag}.gz"
        url = f"{self._release_base}/download/{self._release_tag}/{archive_name}"
        binary = self._workdir / "clash"
        binary.write_bytes(gzip.decompress(self._fetch_archive(url)))
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
        return binary

    def _verify_version(self) -> None:
        assert self._clash is not None
        result = subprocess.run(
            [self._clash, "-v"],
            check=True,
            capture_output=True,
            encoding="utf-8",
        )
        if f"Clash n{self._release_tag}" not in result.stdout:
            raise RuntimeError(f"Unexpected Dreamacro Clash version: {result.stdout.strip()}")

    def check(self, config: Path) -> None:
        assert self._clash is not None
        assert self._workdir is not None
        subprocess.run(
            [self._clash, "-t", "-d", self._workdir, "-f", config],
            check=True,
            capture_output=True,
            encoding="utf-8",
        )
