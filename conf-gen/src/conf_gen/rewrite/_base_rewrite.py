from typing import Any


class RewriteBase:
    def __init__(self, name: str, url: str) -> None:
        self.name = name
        self.url = url
        self._rewrites: list[str] = []

    @property
    def quantumult_rewrite(self) -> list[str]:
        raise NotImplementedError()

    @property
    def clash_rewrite(self) -> Any:
        raise NotImplementedError()
