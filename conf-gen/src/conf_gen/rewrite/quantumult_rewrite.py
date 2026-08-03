from common import COMMENT_BEGINS
from conf_gen._util.fetch import fetch_url
from conf_gen.rewrite._base_rewrite import RewriteBase


class QuantumultRewrite(RewriteBase):
    def __init__(self, name: str, url: str) -> None:
        super().__init__(name, url)

        r = fetch_url(url)
        for line in r.text.splitlines():
            line = line.strip()
            if (
                not line
                or any(line.startswith(prefix) for prefix in COMMENT_BEGINS)
                or line.startswith("hostname")
            ):
                continue
            self._rewrites.append(line)

    @property
    def quantumult_rewrite(self) -> list[str]:
        return self._rewrites
