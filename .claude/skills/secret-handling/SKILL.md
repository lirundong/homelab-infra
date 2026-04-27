---
name: secret-handling
description: Discipline and procedures for the homelab-infra Fernet-encrypted secret system. Auto-loads when reading, writing, or expanding secrets via `_SecretsManager` or `from common import secrets`; when invoking `common-secret-decoder` or `common-rotate-password`; when touching `secrets.yaml`, `@secret:`/`@include:` markers, the `PASSWORD` env var, or the `SALT` env var; when editing the CI workflows that handle `MASTER_PASSWORD`; when building OpenWRT images (which bake secrets into the rootfs); when working with `conf-gen` output (post-secret-expansion configs); or when the user asks about rotating the master password, escrow, leaked-credential remediation, or workflow-artifact encryption. Read fully before suggesting any command that could read, expand, or persist a decrypted secret.
user-invocable: false
---

# Secret handling for homelab-infra

This project encrypts every entry in `common/src/common/secrets.yaml` with a single master password. **One mistake — printing a decrypted value, redirecting it to a transcript-visible stream, baking it into a recordable command — leaks production credentials with no clean expungement path.** This skill is the source of truth for how to work with secrets here.

## Architecture

- **Cipher:** [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC + HMAC-SHA256, AEAD)
- **Key derivation:** PBKDF2HMAC, SHA-256, length 32, 100,000 iterations
- **Inputs:**
  - `PASSWORD` env var → master password (UTF-8 bytes)
  - `SALT` env var (default `19260817`) → salt (UTF-8 bytes)
- **Storage:** `common/src/common/secrets.yaml`, a flat `key: ciphertext` map
- **API:** `from common import secrets; secrets.SOMEKEY` — the `secrets` module replaces itself in `sys.modules` with a `_SecretsManager` instance for attribute-style access. See `common/src/common/_manager.py` and `common/src/common/secrets.py`.
- **CLIs:**
  - `common-secret-decoder` — expand `@secret:` and `@include:` markers in a file or stdin (used at build time)
  - `common-rotate-password` — re-encrypt every entry with a new master (stdin-only; see procedure below)

## Where the master password is bound

Rotating it affects every layer below:

1. **`secrets.yaml`** — Fernet decryption of every entry
2. **GitHub Releases** — used as `gpg --passphrase` for published `.gpg` artifacts (see `.github/workflows/artifacts-release-nightly.yaml`)
3. **Workflow artifacts** — same passphrase encrypts `build_configuration` and `build_openwrt` outputs before `actions/upload-artifact` (encryption added in commit `dcee14b`)
4. **On-device cron** — the OpenWRT image bakes the master into `/etc/crontabs/root`; the daily `gpg -d` of the sing-box config and `register-dns` invocation both consume it

## The hard rule: never surface plaintext secrets in any recorded interaction

A secret plaintext (any value from `secrets.yaml`, the master password, on-device cron credentials, PPPoE/DNS account values, API tokens, anything else marked sensitive) must never appear in:

- `Bash` tool commands or their stdout/stderr
- `Read` tool output for files containing decrypted secrets
- Prompts to subagents or skills
- `Write` / `Edit` content (even temporarily)
- Status messages, smoke-test prints, debug echoes, error messages
- Asking the user to paste a value into the chat

This applies regardless of whether the surface "feels" ephemeral. Anything that runs through a tool call ends up in the session JSONL at `~/.claude/projects/<hash>/<session>.jsonl` (plaintext, 30-day default retention) and is also transmitted to the model provider (commercial-tier 30-day retention by default; longer if data-training is opted in). `/rewind` is a checkpoint-pointer move, not a transcript truncation — it does not erase plaintext from the local JSONL or already-transmitted server-side data. **There is no reliable expungement once it lands.**

### Acceptable verification patterns

- Length / hash / prefix-only assertions: `print(len(value))`, `print(hashlib.sha256(value.encode()).hexdigest()[:8])`
- Compare-to-known and print only a boolean: `print('match:', value == expected_const)`
- Round-trip identity: encrypt-then-decrypt, compare bytes, no values printed
- Decrypt-success-only: catch and print exception class name on failure (`OK` / `FAIL`)

### Acceptable patterns for passing secrets into a process

- **stdin redirect from a file path on argv** (`common-rotate-password < /dev/shm/.rotation/master-new`) — the *path* is on argv, not the value
- **Pre-set environment variable from outside Claude Code** (set in a shell before launching the session, or in `~/.claude/settings.json`)
- **`getpass`-style prompt** that reads from `/dev/tty` directly, never from stdin — only safe when run in a terminal Claude doesn't proxy

### Forbidden

- `PASSWORD='<inline-value>' command …` — the value lands in shell history *and* the transcript
- `! export PASSWORD=…` in Claude Code — the user's input echoes into `~/.claude/history.jsonl` (line 455 of that file picked up exactly such a leak in this project's history)
- Asking the user to paste the value into chat
- Echoing decrypted entries to verify rotation worked
- Logging or `Read`-ing files that contain decrypted material into the conversation

## Master password rotation — full procedure

Use this when the master is compromised, on a periodic schedule, or when forking the project. The procedure was developed and validated end-to-end in commits `d8ee863` (CLI + atomicity), `e248092` (rotation), `dcee14b` (workflow encryption fix).

### Pre-flight checks

1. **Workflow trigger calendar.** `grep -nE 'schedule:|cron:' .github/workflows/artifacts-release-nightly.yaml`. Rotate during a quiet window so a scheduled run doesn't fire mid-rotation.
2. **`@secret:MASTER_PASSWORD` references.** `grep -rn 'MASTER_PASSWORD' conf-gen/ openwrt-builder/files/ .github/`. Confirm any references are intentional. The on-device crontab references it; that's acceptable because the OpenWRT image is itself GPG-encrypted with the same master, so no incremental exposure.
3. **Repo visibility.** `gh repo view <owner/repo> --json visibility`. Public repos require workflow-artifact encryption (already in place as of `dcee14b`); fingerprint hashes published to CI logs are world-readable, so the master input must be high-entropy (UUID v4).
4. **Old master is escrowed.** The user must already have the *current* master in a personal store (password manager, etc.) before starting — needed for rollback and to decrypt historical release artifacts.
5. **Workspace clean.** `git status` — no uncommitted changes that could end up bundled with the rotation commit.

### Sequence

```bash
# B0 — close the race window
gh workflow disable artifacts-release-nightly.yaml --repo <owner/repo>

# B1 — generate new master to tmpfs (memory-backed, never paged to swap)
umask 077 && mkdir -p /dev/shm/.rotation
uuidgen -r | tr -d '\n' > /dev/shm/.rotation/master-new
# Sanity: 36 bytes, mode 0600, version digit at pos 14 == '4'
test "$(wc -c < /dev/shm/.rotation/master-new)" -eq 36
test "$(stat -c '%a' /dev/shm/.rotation/master-new)" = 600
test "$(cut -c15 /dev/shm/.rotation/master-new)" = 4

# B1.5 — USER escrows the new master out-of-band (separate terminal, not Claude)
#   pass insert -m homelab/master-password < /dev/shm/.rotation/master-new
#   diff <(pass show homelab/master-password) /dev/shm/.rotation/master-new
# Pause until the user confirms escrow succeeded. After C1 the file is gone
# and the master is recoverable only from this escrow.

# B2 — upload to GitHub via stdin (value never on argv or stdout)
gh secret set MASTER_PASSWORD --repo <owner/repo> < /dev/shm/.rotation/master-new

# B3 — verify GitHub-side bytes match local-side via 16-hex sha256 fingerprint
gh workflow run verify-master-password.yaml --repo <owner/repo>
# Wait for the run to complete, fetch the log, extract the 16-hex line.
# Compare to: sha256sum < /dev/shm/.rotation/master-new | cut -c1-16
# Mismatch → re-run B2.

# B4 — rotate local secrets.yaml
PASSWORD='<old-master-from-escrow>' uv run common-rotate-password \
    < /dev/shm/.rotation/master-new
# Decrypts every entry with old fernet, derives new fernet, re-encrypts,
# atomically swaps via temp + flush + fsync + chmod-preserve + os.replace
# + dir-fsync. See _manager.py:rotate_password.

# B5 — fresh-process round-trip; boolean only
PASSWORD="$(cat /dev/shm/.rotation/master-new)" uv run python3 -c '
from common import secrets
import sys
ok = sum(1 for k in secrets._encrypted_secrets if getattr(secrets, k))
sys.exit(0 if ok == len(secrets._encrypted_secrets) else 1)'

# B6 — commit (with [no release] until the router is re-flashed)
git add common/src/common/secrets.yaml
git commit -m "[common] rotate secrets.yaml master password [no release]"

# B7 — re-enable workflow
gh workflow enable artifacts-release-nightly.yaml --repo <owner/repo>

# B8 — push (triggers CI on the new tip; build_configuration is the integration test)
git push origin master

# B9 — watch CI
gh run watch <run-id>

# C1 — clean up tmpfs
rm -f /dev/shm/.rotation/master-new && rmdir /dev/shm/.rotation
```

### Why each step is the way it is

- **B0/B7 (disable/enable):** between B2 and B8, GitHub holds the new master while master-branch still has old-encrypted `secrets.yaml`. Any unrelated push or scheduled cron in that window would fail in `build_configuration`. Disabling the workflow collapses the race window to zero.
- **B1.5 (escrow before any destructive step):** if anything fails after B2, recovery requires the new master. After C1 the file is gone. Without escrow, the rotation is one-way with no rollback.
- **B3 (fingerprint comparison):** GitHub secrets are write-only. The 16-hex SHA-256 prefix is a fingerprint, safe for public CI logs given UUID v4 entropy. **Do not** publish a fingerprint of a non-UUID password — short or low-entropy inputs become brute-forceable from the prefix.
- **B4 stdin-only CLI:** `--new-password-stdin` pattern keeps the value off argv and out of `/proc/<pid>/cmdline`, shell history, audit logs. The CLI refuses an interactive TTY to avoid terminal echo. Strips one trailing `\n` (`gh secret set < file` also strips one — alignment depends on this).
- **B6 `[no release]`:** the deployed router still has the old master baked into its image. Without `[no release]`, the very next CI run publishes a new-master-encrypted release that the router cannot decrypt at `30 0 * * *`. Keep `[no release]` on every subsequent commit until the router is re-flashed.

### Recovery paths

| Failure | State on disk | Recovery |
|---|---|---|
| B3 fingerprint mismatch | GH secret possibly wrong | Re-run B2 |
| B4 raises before write | `secrets.yaml` untouched | Re-set GH to old: `gh secret set MASTER_PASSWORD --repo … <<<"$(pass show old-master)"`. Investigate, retry. |
| B5 fails (corrupt rotated file) | local `secrets.yaml` rotated, not yet pushed | `git checkout -- common/src/common/secrets.yaml`. Re-set GH to old. Abort. |
| B8 push fails | local rotated, GH has new master | Retry push promptly; window of broken CI is the duration |
| B9 CI fails | repo + GH consistent in theory | Re-trigger; if persistent, B3 was wrong |

### After rotation — outstanding work for the user

- **Re-flash the router** with a locally-built image using the new master from escrow. Use `bash openwrt-builder/build.sh` with `PASSWORD=$(pass show homelab/master-password)`.
- **Keep `[no release]` on subsequent commits** until the router is re-flashed.
- **Consider rotating non-master secrets** (`PPPOE_*`, `JP_NODE_*`, `NAIVE_PROXY_*`, `CLASH_*`, `SUBSCRIPTION_*`, `DOT_PUB`) at the upstream services — the master rotation doesn't invalidate them, and they may have been leaked via past unencrypted workflow artifacts.
- **Delete pre-rotation workflow artifacts** if they pre-date the encryption fix (`dcee14b`): `gh api -X DELETE /repos/<owner/repo>/actions/artifacts/<id>`.
- **Old GitHub Releases** remain encrypted with the old master; if you care, manually delete via `gh release delete-asset`.

## Workflow-artifact encryption

`actions/upload-artifact` does not encrypt. On a public repo, anyone with read access can download workflow artifacts via the REST API for the retention window (default 90 days, configurable via `retention-days`). As of commit `dcee14b`:

1. **`build_configuration`** GPG-encrypts every non-`.srs` file in `artifacts-conf/` before upload-artifact (`.srs` rule sets are public domain lists, intentionally plaintext).
2. **`build_openwrt`** decrypts the configs from `build_configuration`'s artifact, runs `build.sh`, then GPG-encrypts every `.gz` build output before upload-artifact.
3. **`release_proxy_configurations`** and **`release_openwrt_builds`** download the already-encrypted artifacts and `cp` them into the release directory — no second encryption pass.

If you ever modify these jobs: **encrypt before upload, decrypt at consumer**. Never `upload-artifact` a file containing decrypted material on a public repo. Use `retention-days: 7` on encrypted uploads as belt-and-suspenders.

## Verify-master-password workflow

`.github/workflows/verify-master-password.yaml` is a `workflow_dispatch`-only workflow that emits the first 16 hex chars of `sha256(MASTER_PASSWORD)`. Used in B3 of the rotation procedure to confirm the GitHub secret upload bytes match local. Hardenings: `permissions: {}` (no `GITHUB_TOKEN` scopes), `if: github.actor == 'lirundong'`. The truncated hash is fingerprint-safe **only** for high-entropy inputs; if a future rotation uses anything other than `uuidgen -r` output, raise the truncation length or use HMAC with a separate verification key.

## Footguns

- **`! export PASSWORD=…` writes the value into `~/.claude/history.jsonl`.** Don't do this. Pass via file or pre-set env from outside Claude Code.
- **`PASSWORD=$(cat …) command`**: the substituted command itself appears in the transcript. Prefer `command < /path/to/file` (stdin redirect).
- **Editable install**: `uv run common-rotate-password` always picks up the current source of `common/src/common/_rotate_password.py` (workspace editable install). If behavior surprises you, audit `__pycache__` for stale bytecode rather than the source.
- **`os.replace` cross-filesystem**: `os.replace` is atomic only on the same filesystem. `_SecretsManager.rotate_password` puts `*.tmp` next to `secrets.yaml` for this reason. Don't change that.
- **`uuidgen -r` not `uuidgen`**: bare `uuidgen` may produce v1 (MAC-derived) UUIDs on BSD-derived platforms, dropping effective entropy from ~122 bits to ~60. Always `-r` for v4.
- **`gh secret set` strips one trailing `\n` from stdin.** If the local file has the newline and the rotation CLI doesn't strip it (or vice versa), the local secrets.yaml encryption diverges from GitHub's and CI fails. Both sides must be consistent — current implementation: file has no `\n` (`uuidgen | tr -d '\n'`), CLI strips one if present.

## Cross-references

- `README.md` (top-level) — public-facing summary of the encryption construction
- `common/src/common/_manager.py` — `_SecretsManager` implementation including `rotate_password`
- `common/src/common/_rotate_password.py` — stdin-only rotation CLI
- `common/src/common/_cli.py` — `common-secret-decoder` for expanding markers in files
- `.github/workflows/artifacts-release-nightly.yaml` — encrypted-artifact pipeline
- `.github/workflows/verify-master-password.yaml` — fingerprint comparison
- Project `CLAUDE.md` — `common — Secrets Management` section for the high-level model
