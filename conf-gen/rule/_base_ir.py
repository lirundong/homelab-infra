class IRBase:

    _clash_prefix = None
    _quantumult_prefix = None
    _sing_box_prefix = None
    _might_resolvable = False

    def __init__(self, val, resolve=None):
        if self._might_resolvable and resolve is None:
            raise ValueError(
                f"{self.__class__.__name__} requires explicitly specify whether this rule requires "
                f"hostname resolution, but got resolve={resolve}"
            )
        self._val = val
        self._resolve = resolve

    def __hash__(self):
        return hash(
            f"{self._clash_prefix},"
            f"{self._quantumult_prefix},"
            f"{self._sing_box_prefix},"
            f"{self._might_resolvable},"
            f"{self._val},"
            f"{self._resolve},"
        )

    def __eq__(self, rhs):
        return type(rhs) == type(self) and rhs._val == self._val

    @property
    def clash_rule(self):
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
    def quantumult_rule(self):
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
    def sing_box_rule(self):
        if self._sing_box_prefix is None:
            raise ValueError(f"{self.__class__.__name__} is not supported by sing-box.")
        return self._sing_box_prefix, self._val


class IRRegistry:
    def __init__(self):
        self._registry = {}

    def register(self):
        def _do_register(cls):
            assert issubclass(cls, IRBase), f"{cls} is not a subclass of IRBase"
            if cls._clash_prefix is not None:
                self._registry[cls._clash_prefix.lower()] = cls
            if cls._quantumult_prefix is not None:
                self._registry[cls._quantumult_prefix.lower()] = cls
            if cls._sing_box_prefix is not None:
                self._registry[cls._sing_box_prefix.lower()] = cls
            return cls

        return _do_register

    def __contains__(self, key):
        if key.lower() in self._registry:
            return True
        else:
            return False

    def __getitem__(self, key):
        if key.lower() in self._registry:
            return self._registry[key.lower()]
        else:
            raise RuntimeError(f"{key} was not registered as an IR.")


_IR_REGISTRY = IRRegistry()
