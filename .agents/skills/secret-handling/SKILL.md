---
name: secret-handling
description: Discipline and procedures for the homelab-infra Fernet-encrypted secret system. Auto-loads when reading, writing, or expanding secrets via `_SecretsManager` or `from common import secrets`; when invoking `common-secret-decoder` or `common-rotate-password`; when touching `secrets.yaml`, `@secret:`/`@include:` markers, the `PASSWORD` env var, or the `SALT` env var; when editing the CI workflows that handle `MASTER_PASSWORD`; when building OpenWRT images (which bake secrets into the rootfs); when working with `conf-gen` output (post-secret-expansion configs); or when the user asks about rotating the master password, escrow, leaked-credential remediation, or workflow-artifact encryption. Read fully before suggesting any command that could read, expand, or persist a decrypted secret.
user-invocable: false
---

# Secret handling for homelab-infra

This project encrypts every entry in `common/src/common/secrets.yaml` with a single master
password. **One mistake — printing a decrypted value, redirecting it to a transcript-visible
stream, baking it into a recordable command — leaks production credentials with no clean
expungement path.** This file is the source of truth for the *daily-use* discipline.

For the rare operations that need their own playbook (don't read these until you actually
need them — progressive disclosure keeps everyday context lean):

- [Rotating the master password](references/rotation.md)
- [Workflow-artifact encryption + the `verify-master-password.yaml` workflow][artifact-enc]

[artifact-enc]: references/artifact-encryption.md

## Architecture

- **Cipher:** [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC + HMAC-SHA256,
  AEAD)
- **Key derivation:** PBKDF2HMAC, SHA-256, length 32, 100,000 iterations
- **Inputs:**
  - `PASSWORD` env var → master password (UTF-8 bytes)
  - `SALT` env var (default `19260817`) → salt (UTF-8 bytes)
- **Storage:** `common/src/common/secrets.yaml`, a flat `key: ciphertext` map
- **API:** `from common import secrets; secrets.SOMEKEY` — the `secrets` module replaces
  itself in `sys.modules` with a `_SecretsManager` instance for attribute-style access. See
  `common/src/common/_manager.py` and `common/src/common/secrets.py`.
- **CLIs:**
  - `common-secret-decoder` — expand `@secret:` and `@include:` markers in a file or stdin
    (used at build time)
  - `common-rotate-password` — re-encrypt every entry with a new master (stdin-only; see
    [references/rotation.md](references/rotation.md))

## Where the master password is bound

Rotating it affects every layer below — *read [references/rotation.md](references/rotation.md)
before touching any of these*:

1. **`secrets.yaml`** — Fernet decryption of every entry
2. **GitHub Releases** — `gpg --passphrase` for published `.gpg` artifacts (see
   `.github/workflows/artifacts-release-nightly.yaml`)
3. **Workflow artifacts** — same passphrase encrypts `build_configuration` and
   `build_openwrt` outputs before `actions/upload-artifact` (see
   [references/artifact-encryption.md](references/artifact-encryption.md))
4. **On-device cron** — the OpenWRT image bakes the master into `/etc/crontabs/root`; the
   daily `gpg -d` of the sing-box config and `register-dns` invocation both consume it

## The hard rule: never surface plaintext secrets in any recorded interaction

A secret plaintext (any value from `secrets.yaml`, the master password, on-device cron
credentials, PPPoE/DNS account values, API tokens, anything else marked sensitive) must
never appear in:

- `Bash` tool commands or their stdout/stderr
- `Read` tool output for files containing decrypted secrets
- Prompts to subagents or skills
- `Write` / `Edit` content (even temporarily)
- Status messages, smoke-test prints, debug echoes, error messages
- Asking the user to paste a value into the chat

This applies regardless of whether the surface "feels" ephemeral. Anything that runs through
a tool call ends up in the session JSONL at `~/.claude/projects/<hash>/<session>.jsonl`
(plaintext, 30-day default retention) and is also transmitted to the model provider
(commercial-tier 30-day retention by default; longer if data-training is opted in).
`/rewind` is a checkpoint-pointer move, not a transcript truncation — it does not erase
plaintext from the local JSONL or already-transmitted server-side data. **There is no
reliable expungement once it lands.**

### Acceptable verification patterns

- Length / hash / prefix-only assertions: `print(len(value))`,
  `print(hashlib.sha256(value.encode()).hexdigest()[:8])`
- Compare-to-known and print only a boolean: `print('match:', value == expected_const)`
- Round-trip identity: encrypt-then-decrypt, compare bytes, no values printed
- Decrypt-success-only: catch and print exception class name on failure (`OK` / `FAIL`)

### Acceptable patterns for passing secrets into a process

- **stdin redirect from a file path on argv**
  (`common-rotate-password < /dev/shm/.rotation/master-new`) — the *path* is on argv, not
  the value
- **Pre-set environment variable from outside Claude Code** (set in a shell before launching
  the session, or in `~/.claude/settings.json`)
- **`getpass`-style prompt** that reads from `/dev/tty` directly, never from stdin — only
  safe when run in a terminal Claude doesn't proxy

### Forbidden

- `PASSWORD='<inline-value>' command …` — the value lands in shell history *and* the
  transcript
- `! export PASSWORD=…` in Claude Code — the user's input echoes into
  `~/.claude/history.jsonl` (line 455 of that file picked up exactly such a leak in this
  project's history)
- Asking the user to paste the value into chat
- Echoing decrypted entries to verify rotation worked
- Logging or `Read`-ing files that contain decrypted material into the conversation

## Footguns

- **`! export PASSWORD=…` writes the value into `~/.claude/history.jsonl`.** Don't do this.
  Pass via file or pre-set env from outside Claude Code.
- **`PASSWORD=$(cat …) command`**: the substituted command itself appears in the transcript.
  Prefer `command < /path/to/file` (stdin redirect).
- **Editable install**: `uv run common-rotate-password` always picks up the current source
  of `common/src/common/_rotate_password.py` (workspace editable install). If behavior
  surprises you, audit `__pycache__` for stale bytecode rather than the source.
- **`os.replace` cross-filesystem**: `os.replace` is atomic only on the same filesystem.
  `_SecretsManager.rotate_password` puts `*.tmp` next to `secrets.yaml` for this reason.
  Don't change that.

## Cross-references

- `README.md` (top-level) — public-facing summary of the encryption construction
- `common/src/common/_manager.py` — `_SecretsManager` implementation including
  `rotate_password`
- `common/src/common/_rotate_password.py` — stdin-only rotation CLI
- `common/src/common/_cli.py` — `common-secret-decoder` for expanding markers in files
- `AGENTS.md` (project root) — `common — Secrets Management` section for the high-level
  model
- [references/rotation.md](references/rotation.md) — full master-password rotation procedure
- [references/artifact-encryption.md](references/artifact-encryption.md) — workflow-artifact
  encryption + the `verify-master-password.yaml` workflow
