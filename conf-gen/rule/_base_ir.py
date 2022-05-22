class IRBase:

    _clash_prefix = None
    _quantumult_prefix = None

    def __init__(self, val):
        self._val = val

    def __hash__(self):
        return hash(f"{self._clash_prefix},{self._quantumult_prefix},{self._val}")

    def __eq__(self, rhs):
        return type(rhs) == type(self) and rhs._val == self._val

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
