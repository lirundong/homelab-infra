import os

# `common.secrets` requires a master password at import; tests never decrypt real secrets.
os.environ.setdefault("PASSWORD", "test-only")
