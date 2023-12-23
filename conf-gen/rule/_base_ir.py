from typing import Any, Callable, Dict, Hashable, Optional, Tuple, Type


class IRBase:

    _clash_prefix: Optional[str] = None
    _quantumult_prefix: Optional[str] = None
    _sing_box_prefix: Optional[str] = None
    _might_resolvable: bool = False

    def __init__(self, val: str, resolve: Optional[bool]=None):
        if self._might_resolvable and resolve is None:
            raise ValueError(
                f"{self.__class__.__name__} requires explicitly specify whether this rule requires "
                f"hostname resolution, but got resolve={resolve}"
            )
        self._val = val
        self._resolve = resolve

    def __hash__(self) -> int:
        return hash(
            f"{self._clash_prefix},"
            f"{self._quantumult_prefix},"
            f"{self._sing_box_prefix},"
            f"{self._might_resolvable},"
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
        self._registry: Dict[str, Type[IRBase]] = {}

    def register(self) -> Callable[[Type[IRBase]], Type[IRBase]]:
        def _do_register(cls: Type[IRBase]) -> Type[IRBase]:
            assert issubclass(cls, IRBase), f"{cls} is not a subclass of IRBase"
            if cls._clash_prefix is not None:
                self._registry[cls._clash_prefix.lower()] = cls
            if cls._quantumult_prefix is not None:
                self._registry[cls._quantumult_prefix.lower()] = cls
            if cls._sing_box_prefix is not None:
                self._registry[cls._sing_box_prefix.lower()] = cls
            return cls

        return _do_register

    def __contains__(self, key: Hashable) -> bool:
        if isinstance(key, str) and key.lower() in self._registry:
            return True
        else:
            return False

    def __getitem__(self, key: Hashable) -> Type[IRBase]:
        if isinstance(key, str) and key.lower() in self._registry:
            return self._registry[key.lower()]
        else:
            raise RuntimeError(f"{key} was not registered as an IR.")


_IR_REGISTRY: IRRegistry = IRRegistry()
