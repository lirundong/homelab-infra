import requests

from rewrite._base_rewrite import RewriteBase
from common import QUANTUMULT_COMMENT_BEGINS


class QuantumultRewrite(RewriteBase):
    def __init__(self, name, url):
        super().__init__(name, url)

        r = requests.get(url)
        if r.status_code != 200:
            raise requests.HTTPError(r.reason)
        for l in r.text.splitlines():
            l = l.strip()
            if (
                not l
                or any(l.startswith(prefix) for prefix in QUANTUMULT_COMMENT_BEGINS)
                or l.startswith("hostname")
            ):
                continue
            self._rewrites.append(l)

    @property
    def quantumult_rewrite(self):
        return self._rewrites
