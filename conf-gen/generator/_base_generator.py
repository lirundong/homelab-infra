from copy import copy
from datetime import datetime

from pytz import timezone


class GeneratorBase:

    _SUPPORTED_PROXY_TYPE = None
    _DEFAULT_PROXY_NAMES = {"PROXY", "DIRECT", "REJECT"}

    def __init__(self, src_file, proxies, proxy_groups):
        self.src_file = src_file
        self._proxies = []
        self._proxy_groups = []
        proxy_names = set(pg.name for pg in proxy_groups).union(self._DEFAULT_PROXY_NAMES)
        for proxy in proxies:
            if type(proxy) in self._SUPPORTED_PROXY_TYPE:
                self._proxies.append(proxy)
                proxy_names.add(proxy.name)
        for proxy_group in proxy_groups:
            proxy_group = copy(proxy_group)
            proxy_group._proxies = [p for p in proxy_group._proxies if p in proxy_names]
            self._proxy_groups.append(proxy_group)

    @property
    def header(self):
        info = "# " + "=" * 78 + "\n"
        info += f"# THIS FILE IS AUTO-GENERATED FROM: {self.src_file}\n"
        info += f"# AT {datetime.now(timezone('Asia/Shanghai')).strftime('%Y/%m/%d %H:%M')}.\n"
        info += "# " + "=" * 78
        return info

    def generate(self, file):
        raise NotImplementedError()
