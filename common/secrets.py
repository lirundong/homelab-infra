import base64
import os
from pydoc import locate
import re
import sys
from typing import Any, Iterable, Mapping

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import yaml


class _SecretsManager:

    _secrets_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "secrets.yaml")
    _secret_prompt = r"@secret:(\w+)(:?\!(\w+))?"  # @secret:<SECRET_NAME>[!<SECRET_TYPE>] 

    def __init__(self) -> None:
        if "PASSWORD" not in os.environ:
            raise RuntimeError("Master password is not set, please assign with PASSWORD environment variable.")

        self._password = str(os.environ["PASSWORD"])
        self._salt = str(os.environ.get("SALT", "19260817"))
        self._encrypted_secrets = yaml.load(open(self._secrets_file, "r", encoding="utf-8"), Loader=yaml.SafeLoader)

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
    
    @property
    def fernet(self):
        return self._fernet
    
    def __getattr__(self, name: str) -> Any:
        if name in self._encrypted_secrets:
            cypher_text = self._encrypted_secrets[name].encode("utf-8")
            plain_text = self._fernet.decrypt(cypher_text).decode("utf-8")
            return plain_text
        else:
            raise AttributeError(f"{name} was not registered as a secret in {self._secrets_file}.")
    
    def _expand_secret(self, match_obj: re.Match) -> str:
        secret_key = match_obj.group(1)
        if secret_key == "MASTER_PASSWORD":
            return self._password
        else:
            return getattr(self, secret_key)
    
    def expand_secret(self, original_str: str) -> Any:
        full_match = re.fullmatch(self._secret_prompt, original_str)
        if full_match and full_match.group(3) is not None:  # Secrets with type.
            t = locate(full_match.group(3))
            v = getattr(self, full_match.group(1))
            return t(v)
        else:
            return re.sub(self._secret_prompt, self._expand_secret, original_str)
    
    def expand_secret_object(self, original_obj: Any) -> Any:
        original_type = type(original_obj)
        if isinstance(original_obj, str):
            return self.expand_secret(original_obj)
        elif isinstance(original_obj, Mapping):
            return original_type(
                [(self.expand_secret_object(k), self.expand_secret_object(v)) for k, v in original_obj.items()]
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
