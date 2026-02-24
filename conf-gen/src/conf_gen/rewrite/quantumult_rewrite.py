import requests

from conf_gen.rewrite._base_rewrite import RewriteBase
from common import COMMENT_BEGINS


class QuantumultRewrite(RewriteBase):
    def __init__(self, name: str, url: str) -> None:
        super().__init__(name, url)

        r = requests.get(url)
        if r.status_code != 200:
            raise requests.HTTPError(r.reason)
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
