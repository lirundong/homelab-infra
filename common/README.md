# Common - Secrets Management Package

Encrypted secrets management for homelab infrastructure with Fernet encryption.

## Installation

```bash
uv sync            # from repo root, installs all workspace packages
# or standalone:
pip install -e ./common
```

## Usage

```python
from common import secrets

# Access secrets
api_key = secrets.MY_API_KEY

# Expand templates
expanded = secrets.expand_secret("@secret:MY_KEY")
config = {"key": "@secret:MY_KEY"}
expanded_config = secrets.expand_secret_object(config)

# Manage secrets
secrets.update("NEW_KEY", "plaintext_value")
secrets.commit()
```

## CLI Tool

```bash
uv run common-secret-decoder source.txt destination.txt
uv run common-secret-decoder -r source_dir/ dest_dir/ -e '.*\.skip$'
echo "@secret:MY_KEY" | uv run common-secret-decoder
```

## Template Syntax

- `@secret:KEY` - Returns string value
- `@secret:KEY!int` - Returns int(value)
- `@secret:MASTER_PASSWORD` - Special key for master password
- `@include:path/to/file` - Include file content (strips comments)

## Environment Variables

- `PASSWORD` (required): Master password
- `SALT` (optional): PBKDF2 salt (default: "19260817")
- `SECRETS_FILE` (optional): Override secrets.yaml location
- `PROJECT_ROOT` (optional): Base path for @include: relative paths
