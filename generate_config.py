"""Generate config files for various clients from a common source spec."""

from argparse import ArgumentParser
from copy import copy
from datetime import datetime
import os
from pytz import timezone
import re

import requests
import yaml


# TODO: Refactor each section to submodules.

# Proxy and subscription.
class ProxyBase:
    def __init__(self, name, server, port):
        self.name = name
        self.server = server
        self.port = port

    @property
    def clash_proxy(self):
        raise NotImplementedError()

    @property
    def quantumult_proxy(self):
        raise NotImplementedError()


class VMessProxy(ProxyBase):
    def __init__(self, name, server, port, uuid, alter_id, cipher, udp=False):
        super().__init__(name, server, port)
        self.uuid = uuid
        self.alter_id = alter_id
        self.cipher = cipher
        self.udp = udp

    @property
    def clash_proxy(self):
        return {
            "alterId": self.alter_id,
            "cipher": self.cipher,
            "name": self.name,
            "port": self.port,
            "server": self.server,
            "type": "vmess",
            "udp": self.udp,
            "uuid": self.uuid,
        }

    @property
    def quantumult_proxy(self):
        method = "chacha20-ietf-poly1305" if self.cipher == "auto" else self.cipher
        info = [
            ("vmess", f"{self.server}:{self.port}",),
            ("method", method,),
            ("password", f"{self.uuid}",),
            ("udp-relay", f"{self.udp}".lower(),),
            ("tag", f"{self.name}",),
        ]
        return ",".join(f"{k}={v}" for k, v in info)


class VMessWebSocketProxy(VMessProxy):
    def __init__(
        self,
        name,
        server,
        port,
        uuid,
        alter_id,
        cipher,
        udp=False,
        tls=True,
        skip_cert_verify=False,
        **ws_options,
    ):
        super().__init__(name, server, port, uuid, alter_id, cipher, udp=udp)
        self.tls = tls
        self.skip_cert_verify = skip_cert_verify
        self.ws_options = ws_options

    @property
    def clash_proxy(self):
        info = super().clash_proxy
        info.update(
            {"tls": self.tls, "skip-cert-verify": self.skip_cert_verify, "network": "ws",}
        )
        if self.ws_options:
            info["ws-opts"] = copy(self.ws_options)
        return info

    @property
    def quantumult_proxy(self):
        info = [
            ("vmess", f"{self.server}:{self.port}",),
            ("method", f"{self.cipher}",),
            ("password", f"{self.uuid}",),
            ("udp-relay", f"{self.udp}".lower(),),
            ("obfs", "wss"),
            ("obfs-uri", f"{self.ws_options['path']}"),
            ("tls-verification", f"{not self.skip_cert_verify}".lower()),
            ("tag", f"{self.name}",),
        ]
        return ",".join(f"{k}={v}" for k, v in info)


class ShadowSocksProxy(ProxyBase):
    def __init__(self, name, server, port, password, cipher, udp=False):
        super().__init__(name, server, port)
        self.password = password
        self.cipher = cipher
        self.udp = udp

    @property
    def clash_proxy(self):
        return {
            "cipher": self.cipher,
            "name": self.name,
            "password": self.password,
            "port": self.port,
            "server": self.server,
            "type": "ss",
            "udp": self.udp,
        }

    @property
    def quantumult_proxy(self):
        info = [
            ("shadowsocks", f"{self.server}:{self.port}",),
            ("method", f"{self.cipher}",),
            ("password", f"{self.password}",),
            ("udp-relay", f"{self.udp}".lower(),),
            ("tag", f"{self.name}",),
        ]
        return ",".join(f"{k}={v}" for k, v in info)


def parse_clash_proxies(proxies_info):
    ret = []
    for proxy_info in proxies_info:
        if proxy_info["type"] == "ss":
            proxy = ShadowSocksProxy(
                name=proxy_info["name"],
                server=proxy_info["server"],
                port=proxy_info["port"],
                password=proxy_info["password"],
                cipher=proxy_info["cipher"],
                udp=proxy_info.get("udp", False),
            )
        elif proxy_info["type"] == "vmess":
            if proxy_info.get("network", None) == "ws":
                proxy = VMessWebSocketProxy(
                    name=proxy_info["name"],
                    server=proxy_info["server"],
                    port=proxy_info["port"],
                    uuid=proxy_info["uuid"],
                    alter_id=proxy_info["alterId"],
                    cipher=proxy_info["cipher"],
                    udp=proxy_info.get("udp", False),
                    tls=proxy_info["tls"],
                    skip_cert_verify=proxy_info["skip-cert-verify"],
                    **proxy_info.get("ws-opts", {}),
                )
            else:
                proxy = VMessProxy(
                    name=proxy_info["name"],
                    server=proxy_info["server"],
                    port=proxy_info["port"],
                    uuid=proxy_info["uuid"],
                    alter_id=proxy_info["alterId"],
                    cipher=proxy_info["cipher"],
                    udp=proxy_info.get("udp", False),
                )
        else:
            raise RuntimeError(f"Get unsupported proxy type: {proxy_info['type']}")
        ret.append(proxy)

    return ret


def parse_clash_subscription(url):
    r = requests.get(url, headers={"user-agent": "clash"})
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)
    return parse_clash_proxies(yaml.load(r.text, Loader=yaml.SafeLoader)["proxies"])


def parse_subscriptions(subscriptions_info):
    proxies = []
    for sub_info in subscriptions_info:
        type = sub_info["type"]
        url = sub_info["url"]
        if type == "clash":
            proxies += parse_clash_subscription(url)
        else:
            raise ValueError(f"Not supported subscription type: {type}")
    return proxies


# Rule.
class IRBase:

    _clash_prefix = None
    _quantumult_prefix = None

    def __init__(self, val):
        self._val = val

    @property
    def clash_rule(self):
        if self._clash_prefix is None:
            raise ValueError(f"{self.__class__.__name__} is not supported by clash.")
        return f"{self._clash_prefix},{self._val}"

    @property
    def quantumult_rule(self):
        if self._quantumult_prefix is None:
            raise ValueError(f"{self.__class__.__name__} is not supported by quantumult x.")
        return f"{self._quantumult_prefix},{self._val}"


class IRRegistry:
    def __init__(self):
        self._registry = {}

    def register(self):
        def _do_register(cls):
            assert issubclass(cls, IRBase), f"{cls} is not a subclass of IRBase"
            if cls._clash_prefix is not None:
                self._registry[cls._clash_prefix] = cls
            if cls._quantumult_prefix is not None:
                self._registry[cls._quantumult_prefix] = cls
            return cls

        return _do_register
    
    def __contains__(self, key):
        if key.lower() in self._registry or key.upper() in self._registry:
            return True
        else:
            return False

    def __getitem__(self, key):
        if key.lower() in self._registry:
            return self._registry[key.lower()]
        elif key.upper() in self._registry:
            return self._registry[key.upper()]
        else:
            raise RuntimeError(f"{key} was not registered as an IR.")


_IR_REGISTRY = IRRegistry()


@_IR_REGISTRY.register()
class UserAgent(IRBase):

    _clash_prefix = None
    _quantumult_prefix = "user-agent"


@_IR_REGISTRY.register()
class ProcessName(IRBase):

    _clash_prefix = "PROCESS-NAME"
    _quantumult_prefix = None


@_IR_REGISTRY.register()
class Domain(IRBase):

    _clash_prefix = "DOMAIN"
    _quantumult_prefix = "host"


@_IR_REGISTRY.register()
class DomainSuffix(IRBase):

    _clash_prefix = "DOMAIN-SUFFIX"
    _quantumult_prefix = "host-suffix"


@_IR_REGISTRY.register()
class DomainKeyword(IRBase):

    _clash_prefix = "DOMAIN-KEYWORD"
    _quantumult_prefix = "host-keyword"


@_IR_REGISTRY.register()
class GeoIP(IRBase):

    _clash_prefix = "GEOIP"
    _quantumult_prefix = "geoip"


@_IR_REGISTRY.register()
class IPCIDR(IRBase):

    _clash_prefix = "IP-CIDR"
    _quantumult_prefix = "ip-cidr"

    @property
    def clash_rule(self):
        return f"{super().clash_rule},no-resolve"


@_IR_REGISTRY.register()
class IPCIDR6(IRBase):

    _clash_prefix = "IP-CIDR6"
    _quantumult_prefix = "ip6-cidr"

    @property
    def clash_rule(self):
        return f"{super().clash_rule},no-resolve"


@_IR_REGISTRY.register()
class SrcIPCIDR(IRBase):

    _clash_prefix = "SRC-IP-CIDR"
    _quantumult_prefix = None


@_IR_REGISTRY.register()
class SrcPort(IRBase):

    _clash_prefix = "SRC-PORT"
    _quantumult_prefix = None


@_IR_REGISTRY.register()
class DstPort(IRBase):

    _clash_prefix = "DST-PORT"
    _quantumult_prefix = None


@_IR_REGISTRY.register()
class Match(IRBase):

    _clash_prefix = "MATCH"
    _quantumult_prefix = "final"

    def __init__(self):
        super().__init__(val=None)

    @property
    def clash_rule(self):
        return self._clash_prefix

    @property
    def quantumult_rule(self):
        return self._quantumult_prefix


_QUANTUMULT_COMMENT_BEGINS = ("#", ";", "//")


def parse_quantumult_filter(url):
    r = requests.get(url)
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)

    ret = []
    for l in r.text.splitlines():
        l = l.strip()
        if not l or any(l.startswith(prefix) for prefix in _QUANTUMULT_COMMENT_BEGINS):
            continue
        type, val = l.split(",")[:2]
        rule_ir = _IR_REGISTRY[type](val)
        ret.append(rule_ir)
    return ret


def parse_clash_classic_filter(url):
    r = requests.get(url, headers={"user-agent": "clash"})
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)

    ret = []
    for l in yaml.load(r.text, Loader=yaml.SafeLoader)["payload"]:
        type, val = l.strip().split(",")[:2]
        rule_ir = _IR_REGISTRY[type](val)
        ret.append(rule_ir)
    return ret


def parse_clash_ipcidr_filter(url):
    r = requests.get(url, headers={"user-agent": "clash"})
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)

    ret = []
    for l in yaml.load(r.text, Loader=yaml.SafeLoader)["payload"]:
        val = l.strip()
        if re.search(r"[0-9]+(?:\.[0-9]+){3}", val):  # Is it IPv4?
            type = "IP-CIDR"
        else:
            type = "IP-CIDR6"
        rule_ir = _IR_REGISTRY[type](val)
        ret.append(rule_ir)
    return ret


def parse_filter(type, **kwargs):
    if type == "quantumult":
        return parse_quantumult_filter(**kwargs)
    elif type == "clash-classic":
        return parse_clash_classic_filter(**kwargs)
    elif type == "clash-ipcidr":
        return parse_clash_ipcidr_filter(**kwargs)
    elif type in _IR_REGISTRY:
        if "arg" in kwargs:
            return [_IR_REGISTRY[type](kwargs["arg"])]
        else:
            return [_IR_REGISTRY[type]()]
    else:
        raise ValueError(f"Unsupported filter type: {type}")


# Proxy group.
class ProxyGroupBase:
    def __init__(self, name, filters, proxies, img_url=None, available_proxies=None):
        self.name = name
        self.img_url = img_url
        self._filters = []
        self._proxies = []

        if filters:  # `filters` could be None, e.g., clash's special PROXY group.
            for filter in filters:
                filter = parse_filter(**filter)
                self._filters += filter

        for proxy in proxies:
            if isinstance(proxy, str):
                self._proxies.append(proxy)
            elif isinstance(proxy, ProxyBase):
                self._proxies.append(proxy.name)
            elif isinstance(proxy, dict) and proxy["type"] == "regex":
                if available_proxies is None:
                    raise ValueError("Must provide non-empty proxy list to use proxy regex.")
                pattern = proxy["pattern"]
                for available_proxy in available_proxies:
                    if re.search(pattern, available_proxy.name):
                        self._proxies.append(available_proxy.name)

    @property
    def quantumult_policy(self):
        raise NotImplementedError()

    @property
    def quantumult_filters(self):
        return [f"{filter.quantumult_rule},{self.name}" for filter in self._filters]

    @property
    def clash_proxy_group(self):
        raise NotImplementedError()

    @property
    def clash_rules(self):
        ret = []
        for filter in self._filters:
            try:
                clash_rule = filter.clash_rule.split(",")
            except ValueError as e:
                if str(e).endswith("is not supported by clash."):
                    continue
                else:
                    raise e
            if clash_rule[-1] == "no-resolve":
                clash_rule.insert(-1, self.name)
            else:
                clash_rule.append(self.name)
            ret.append(",".join(clash_rule))
        return ret


class SelectProxyGroup(ProxyGroupBase):
    def __init__(self, name, filters, proxies, img_url=None, available_proxies=None):
        super().__init__(
            name, filters, proxies, img_url=img_url, available_proxies=available_proxies
        )

    @property
    def quantumult_policy(self):
        info = [f"static={self.name}"]
        info += self._proxies
        if self.img_url:
            info.append(f"img-url={self.img_url}")
        return ",".join(info)

    @property
    def clash_proxy_group(self):
        return {
            "name": self.name,
            "type": "select",
            "proxies": self._proxies,
        }


def parse_proxy_groups(proxy_groups_info, available_proxies=None):
    proxy_groups = []
    for g_info in proxy_groups_info:
        if g_info["type"] == "select":
            g = SelectProxyGroup(
                name=g_info["name"],
                filters=g_info["filters"],
                proxies=g_info["proxies"],
                img_url=g_info["img-url"],
                available_proxies=available_proxies,
            )
        else:
            raise ValueError(f"Unsupported proxy group type: {g_info['type']}.")
        proxy_groups.append(g)

    return proxy_groups


# Rewrite.
class RewriteBase:
    def __init__(self, name, url):
        self.name = name
        self.url = url
        self._rewrites = []

    @property
    def quantumult_rewrite(self):
        raise NotImplementedError()

    @property
    def clash_rewrite(self):
        raise NotImplementedError()


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
                or any(l.startswith(prefix) for prefix in _QUANTUMULT_COMMENT_BEGINS)
                or l.startswith("hostname")
            ):
                continue
            self._rewrites.append(l)

    @property
    def quantumult_rewrite(self):
        return self._rewrites


def parse_rewrites(rewrites_info):
    rewrites = []
    for r_info in rewrites_info:
        if r_info["type"] == "quantumult":
            r = QuantumultRewrite(
                name=r_info["name"],
                url=r_info["url"],
            )
        else:
            raise ValueError(f"Unsupported rewrite type: {r_info['type']}.")
        rewrites.append(r)
    
    return rewrites


# Config generation.
class GeneratorBase:
    def __init__(self, src_file, proxies, proxy_groups):
        self.src_file = src_file
        self._proxies = copy(proxies)
        self._proxy_groups = copy(proxy_groups)

    @property
    def header(self):
        info = "# " + "=" * 78 + "\n"
        info += f"# THIS FILE IS AUTO-GENERATED FROM: {self.src_file}\n"
        info += f"# AT {datetime.now(timezone('Asia/Shanghai')).strftime('%Y/%m/%d %H:%M')}.\n"
        info += "# " + "=" * 78
        return info

    def generate(self, file):
        raise NotImplementedError()


class ClashGenerator(GeneratorBase):
    def __init__(self, src_file, proxies, proxy_groups, **general_options):
        super().__init__(src_file, proxies, proxy_groups)
        self._general_options = general_options

        # Construct special group `PROXY` for clash.
        the_proxy_proxy_group = SelectProxyGroup(name="PROXY", filters=None, proxies=proxies,)
        self._proxy_groups.insert(0, the_proxy_proxy_group)

    def generate(self, file):
        conf = {}
        conf.update(self._general_options)
        conf["proxies"] = [p.clash_proxy for p in self._proxies]
        conf["proxy-groups"] = [g.clash_proxy_group for g in self._proxy_groups]
        conf["rules"] = []
        for g in self._proxy_groups:
            conf["rules"] += g.clash_rules

        base, _ = os.path.split(file)
        os.makedirs(base, exist_ok=True)
        with open(file, "w", encoding="utf-8") as f:
            f.write(f"{self.header}\n")
            yaml.dump(
                conf,
                f,
                Dumper=yaml.SafeDumper,
                allow_unicode=True,
                line_break="\n",
            )


class QuantumultGenerator(GeneratorBase):

    _MANDATORY_SECTIONS = (
        "dns",
        "general",
        "filter_local",
        "filter_remote",
        "policy",
        "server_local",
        "server_remote",
        "rewrite_local",
        "rewrite_remote",
        "task_local",
        "mitm",
    )

    def __init__(self, src_file, proxies, proxy_groups, rewrites, **additional_sections):
        super().__init__(src_file, proxies, proxy_groups)
        self._rewrites = rewrites
        self._additional_sections = additional_sections
    
    @staticmethod
    def parse_tasks(tasks_info):
        ret = []
        for t in tasks_info:
            if t["type"] == "event-interaction":
                task = [
                    f"event-interaction {t['url']}",
                    f"tag={t['name']}",
                    f"img-url={t['img-url']}",
                    "enabled=true",
                ]
                task = ",".join(task)
                ret.append(task)
            else:
                raise ValueError(f"Unsupported task type: {t['type']}.")

        return ret

    def generate(self, file):
        base, _ = os.path.split(file)
        os.makedirs(base, exist_ok=True)
        missing_sections = set(self._MANDATORY_SECTIONS)
        with open(file, "w", encoding="utf-8") as f:
            # Header.
            f.write(f"{self.header}\n")
            # Additional key-value items.
            for section, content in self._additional_sections.items():
                f.write(f"[{section}]\n")
                missing_sections.remove(section)
                if content is None:
                    continue
                elif section == "task_local":
                    for task in self.parse_tasks(content):
                        f.write(f"{task}\n")
                else:
                    for k, v in content.items():
                        if isinstance(v, (list, tuple)):
                            v = ",".join(v)
                        f.write(f"{k}={v}\n")
            # Server.
            f.write("[server_local]\n")
            missing_sections.remove("server_local")
            for p in self._proxies:
                f.write(f"{p.quantumult_proxy}\n")
            # Policy.
            f.write("[policy]\n")
            missing_sections.remove("policy")
            for g in self._proxy_groups:
                f.write(f"{g.quantumult_policy}\n")
            # Filter.
            f.write("[filter_local]\n")
            missing_sections.remove("filter_local")
            for g in self._proxy_groups:
                f.write("\n".join(g.quantumult_filters) + "\n")
            # Rewrite.
            f.write("[rewrite_local]\n")
            missing_sections.remove("rewrite_local")
            for r in self._rewrites:
                f.write("\n".join(r.quantumult_rewrite) + "\n")
            # Other missing sections.
            for section in missing_sections:
                f.write(f"[{section}]\n")


def generate_conf(generate_info, src, dst, proxies, proxy_groups, rewrites=None):
    for gen_info in generate_info:
        if gen_info["type"] == "clash":
            general_options = copy(gen_info)
            general_options.pop("name")
            general_options.pop("type")
            gen = ClashGenerator(
                src_file=src,
                proxies=proxies,
                proxy_groups=proxy_groups,
                **general_options
            )
            dst_filename = os.path.join(dst, f"{gen_info['name']}.yaml")
            gen.generate(dst_filename)
        elif gen_info["type"] == "quantumult":
            if rewrites is None:
                raise ValueError("`rewrites` arg is required for generating Quantumult configs.")
            additional_sections = copy(gen_info)
            additional_sections.pop("name")
            additional_sections.pop("type")
            gen = QuantumultGenerator(
                src_file=src,
                proxies=proxies,
                proxy_groups=proxy_groups,
                rewrites=rewrites,
                **additional_sections
            )
            dst_filename = os.path.join(dst, f"{gen_info['name']}.conf")
            gen.generate(dst_filename)
        else:
            raise ValueError(f"Unsupported generate type: {gen_info['type']}.")


if __name__ == "__main__":
    parser = ArgumentParser("Generate Clash/QuantumultX config from specified source.")
    parser.add_argument("-s", "--src", required=True, help="Source spec in YAML format.")
    parser.add_argument("-o", "--dst", required=True, help="Directory of generated files.")
    args = parser.parse_args()

    src_conf = yaml.load(open(args.src, "r"), Loader=yaml.SafeLoader)
    src_file = os.path.split(args.src)[-1]

    proxies = parse_clash_proxies(src_conf["proxies"])
    proxies += parse_subscriptions(src_conf["subscriptions"])
    proxy_groups = parse_proxy_groups(src_conf["rules"], available_proxies=proxies)
    rewrites = parse_rewrites(src_conf["rewrites"])

    generate_conf(src_conf["generates"], src_file, args.dst, proxies, proxy_groups, rewrites)
