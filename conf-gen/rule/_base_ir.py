import functools
import re
from typing import Any, Callable, Dict, Hashable, Optional, Tuple, Type
from warnings import warn


class IRBase:

    _clash_prefix: Optional[str] = None
    _quantumult_prefix: Optional[str] = None
    _sing_box_prefix: Optional[str] = None
    _might_resolvable: bool = False
    _val_is_domain: Optional[bool] = None

    def __init__(self, val: str, resolve: Optional[bool]=None):
        if self._might_resolvable and resolve is None:
            raise ValueError(
                f"{self.__class__.__name__} requires explicitly specify whether this rule requires "
                f"hostname resolution, but got resolve={resolve}"
            )
        if self._val_is_domain and ":" in val:  # Domain list item contained port number.
            warn(f"Got port numbers in {self.__class__.__name__} item: {val}, trying to remove...")
            val = val.split(":")[0]

        self._val = val
        self._resolve = resolve

    def __hash__(self) -> int:
        return hash(
            f"{self._clash_prefix},"
            f"{self._quantumult_prefix},"
            f"{self._sing_box_prefix},"
            f"{self._might_resolvable},"
            f"{self._val_is_domain}",
            f"{self._val},"
            f"{self._resolve},"
        )

    def __eq__(self, rhs: Any) -> bool:
        return type(rhs) == type(self) and rhs._val == self._val

    @property
    def clash_rule(self) -> str:
        if self._clash_prefix is None:
            raise ValueError(f"{self.__class__.__name__} is not supported by clash.")
        if self._might_resolvable:
            if self._resolve is None:
                raise ValueError(
                    f"{self.__class__.__name__} requires explicitly specify whether this rule "
                    f"requires hostname resolution, but got resolve={self._resolve}"
                )
            elif self._resolve:
                return f"{self._clash_prefix},{self._val}"
            else:
                return f"{self._clash_prefix},{self._val},no-resolve"
        else:
            return f"{self._clash_prefix},{self._val}"

    @property
    def quantumult_rule(self) -> str:
        if self._quantumult_prefix is None:
            raise ValueError(f"{self.__class__.__name__} is not supported by quantumult x.")
        if self._might_resolvable:
            if self._resolve is None:
                raise ValueError(
                    f"{self.__class__.__name__} requires explicitly specify whether this rule "
                    f"requires hostname resolution, but got resolve={self._resolve}"
                )
            elif self._resolve:
                return f"{self._quantumult_prefix},{self._val}"
            else:
                return f"{self._quantumult_prefix},{self._val},no-resolve"
        else:
            return f"{self._quantumult_prefix},{self._val}"

    @property
    def sing_box_rule(self) -> Tuple[str, str]:
        if self._sing_box_prefix is None:
            raise ValueError(f"{self.__class__.__name__} is not supported by sing-box.")
        return self._sing_box_prefix, self._val


class IRRegistry:
    def __init__(self) -> None:
        self._registry: Dict[Tuple[str], Type[IRBase]] = {}

    @staticmethod
    @functools.lru_cache(maxsize=128)
    def prefix2key(prefix: str):
        if not isinstance(prefix, str):
            raise ValueError(f"IRRegistry key must be a string, got {prefix} instead")
        key = tuple(re.split(r"_|-", prefix.lower()))
        return key

    def register(self) -> Callable[[Type[IRBase]], Type[IRBase]]:
        def _do_register(cls: Type[IRBase]) -> Type[IRBase]:
            assert issubclass(cls, IRBase), f"{cls} is not a subclass of IRBase"
            keys = set()
            if cls._clash_prefix is not None:
                keys.add(self.prefix2key(cls._clash_prefix))
            if cls._quantumult_prefix is not None:
                keys.add(self.prefix2key(cls._quantumult_prefix))
            if cls._sing_box_prefix is not None:
                keys.add(self.prefix2key(cls._sing_box_prefix))
            for k in keys:
                self._registry[k] = cls
            return cls

        return _do_register

    def __contains__(self, key: Hashable) -> bool:
        if isinstance(key, str) and self.prefix2key(key) in self._registry:
            return True
        else:
            return False

    def __getitem__(self, key: Hashable) -> Type[IRBase]:
        if isinstance(key, str) and self.prefix2key(key) in self._registry:
            return self._registry[self.prefix2key(key)]
        else:
            raise RuntimeError(f"{key} was not registered as an IR.")


_IR_REGISTRY: IRRegistry = IRRegistry()
