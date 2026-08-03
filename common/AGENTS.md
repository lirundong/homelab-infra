# common

Encrypted secrets management and template expansion for the workspace. Inherit the
repository-root instructions.

## Functionality

`_SecretsManager` derives a Fernet key with PBKDF2HMAC-SHA256 (100,000 iterations).
`PASSWORD` is required; `SALT` defaults to `19260817`. Secret lookup order is
`SECRETS_FILE`, the installed package, the package root, then `/root/common/secrets.yaml`.

The singleton API supports attribute lookup, staged `update`/`status`/`commit`, crash-safe
password rotation, recursive object expansion, and:

- `@secret:KEY[!TYPE]`
- `@include:FILE[:!JOIN][:>INDENT]`

Relative includes resolve from `PROJECT_ROOT`, the Git root, then the current directory.
`common-secret-decoder` expands files or trees; `common-rotate-password` reads the new
password from redirected stdin and rejects a TTY.

## Secret Discipline

Before reading, expanding, changing, or validating secrets, read
`.ai/skills/secret-handling/SKILL.md`. Never surface plaintext secrets in commands, output,
files, logs, or conversation. Do not call `status()` in a recorded session because it prints
staged values. Read the rotation reference only for an actual rotation.

## Validation

```bash
uv run --extra dev mypy common/src/common
uv run --extra dev pre-commit run --all-files
```

There is currently no direct `common` pytest suite or coverage threshold. Its normal CI
coverage is static typing plus indirect use by `conf-gen` tests and OpenWRT builds; changes
to encryption, expansion, or rotation need focused tests rather than relying on that
indirect coverage.
