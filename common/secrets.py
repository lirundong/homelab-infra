import base64
import os
from pathlib import Path
from pprint import pprint
from pydoc import locate
import re
import sys
from typing import Any, Dict, Iterable, Mapping
from warnings import warn

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import yaml


JsonPrimitiveT = str | int | float | bool


class _SecretsManager:

    _secrets_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "secrets.yaml")
    # Insert secrets by literal: @secret:<SECRET_KEY>[!<SECRET_TYPE>]
    _secret_prompt = r"@secret:(?P<key>\w+)(:?\!(?P<type>\w+))?"
    # Insert file content by literal: @include:<FILE_PATH>[!<JOIN_BY>][><INDENT_BY>]
    _include_prompt = r"@include:(?P<file>[\w\-\/\.\\]+)(:?\!(?P<join_by>[\\\w\s]+))?(:?\>(?P<indent_by>\d+))?"
    _comment_begins = ("#", "//", "<!--", "/*")
    _project_root = Path(__file__).parents[1]

    def __init__(self) -> None:
        if "PASSWORD" not in os.environ:
            raise RuntimeError(
                "Master password is not set, please assign with PASSWORD environment variable."
            )

        self._password = str(os.environ["PASSWORD"])
        self._salt = str(os.environ.get("SALT", "19260817"))
        self._encrypted_secrets: Dict[str, str] = yaml.load(
            open(self._secrets_file, "r", encoding="utf-8"), Loader=yaml.SafeLoader
        )

        master_password = self._password.encode("utf-8")
        salt = self._salt.encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password))
        self._fernet = Fernet(key)
        self._staged_changes = dict()

    @property
    def fernet(self):
        return self._fernet

    def __getattr__(self, name: str) -> Any:
        if name in self._encrypted_secrets:
            cypher_text = self._encrypted_secrets[name].encode("utf-8")
            plain_text = self._fernet.decrypt(cypher_text).decode("utf-8")
            return plain_text
        elif name in os.environ:
            warn(
                f"`{name}` was fetched from raw environment variables as it was not registered as a secret."
            )
            return str(os.environ[name])
        else:
            raise AttributeError(
                f"{name} was neither registered as a secret in {self._secrets_file} nor an environment variable."
            )

    def update(self, key: str, value: str):
        if not isinstance(value, str):
            raise ValueError(f"Credential values should be str, but got {type(value)} instead.")
        value = self._fernet.encrypt(value.encode("utf-8")).decode("ascii")
        self._staged_changes[key] = value

    def status(self):
        if self._staged_changes:
            print(f"These credential changes will be written into {self._secrets_file}:")
            pprint(self._staged_changes)

    def commit(self):
        self._encrypted_secrets.update(self._staged_changes)
        print(f"These credentials have been changed:")
        pprint(list(self._staged_changes.keys()))
        self._staged_changes.clear()
        with open(self._secrets_file, "w", encoding="utf-8") as f:
            yaml.dump(self._encrypted_secrets, f, Dumper=yaml.SafeDumper)
        print(f"Changes have been written into {self._secrets_file}")

    def _expand_secret(self, match_obj: re.Match[str]) -> JsonPrimitiveT:
        if (secret_key := match_obj.group("key")) == "MASTER_PASSWORD":
            secret_val = self._password
        else:
            secret_val = getattr(self, secret_key)
            if secret_type := match_obj.group("type"):
                assert issubclass(locate(secret_type), JsonPrimitiveT)
                secret_val = locate(secret_type)(secret_val)
        return secret_val

    def _expand_include(self, match_obj: re.Match[str]) -> str:
        if not (file_path := Path(match_obj.group("file"))).is_absolute():
            file_path = self._project_root / file_path
        if not file_path.exists():
            raise FileNotFoundError(f"File {match_obj.group('file')} not found.")
        if (indent_by := match_obj.group("indent_by")) is not None and int(indent_by) < 0:
            raise ValueError(f"Indent by should be positive, but got {indent_by} instead.")
        lines = []
        join_by = match_obj.group("join_by") or "\n"
        indent_by = int(indent_by) if indent_by else 0
        for i, line in enumerate(file_path.read_text().splitlines()):
            if not line.strip() or line.lstrip().startswith(self._comment_begins):
                continue
            elif i and indent_by:
                # Only indent second and afterwards lines.
                lines.append(" " * indent_by + line.strip())
            else:
                lines.append(line.strip())
        return join_by.join(lines)

    def expand_secret(self, original_str: str) -> Any:
        # Handle full matches first.
        if include_full_match := re.fullmatch(self._include_prompt, original_str):
            return self._expand_include(include_full_match)
        if secret_full_match := re.fullmatch(self._secret_prompt, original_str):
            return self._expand_secret(secret_full_match)
        # For other scenario, expand both include and secrets in cascaded passes
        includes_expanded = re.sub(
            self._include_prompt,
            lambda match: str(self._expand_include(match)),
            original_str,
        )
        secrets_expanded = re.sub(
            self._secret_prompt,
            lambda match: str(self._expand_secret(match)),
            includes_expanded,
        )
        return secrets_expanded

    def expand_secret_object(self, original_obj: Any) -> Any:
        original_type = type(original_obj)
        if isinstance(original_obj, str):
            return self.expand_secret(original_obj)
        elif isinstance(original_obj, Mapping):
            return original_type(
                [
                    (self.expand_secret_object(k), self.expand_secret_object(v))
                    for k, v in original_obj.items()
                ]
            )
        elif isinstance(original_obj, tuple) and hasattr(original_obj, "_fields"):  # namedtuple
            expanded_values = []
            for field in original_obj._fields:
                original_value = getattr(original_obj, field)
                expanded_value = self.expand_secret_object(original_value)
                expanded_values.append(expanded_value)
            return original_type(*expanded_values)
        elif isinstance(original_obj, Iterable):
            return original_type(self.expand_secret_object(v) for v in original_obj)
        else:
            return original_obj


# Allow accessing secrets as module-level attributes, see https://stackoverflow.com/a/880550.
sys.modules[__name__] = _SecretsManager()
