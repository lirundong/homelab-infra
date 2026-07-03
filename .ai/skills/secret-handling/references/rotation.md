# Master password rotation — full procedure

> **Read [../SKILL.md](../SKILL.md) first** — the hard rule on never surfacing plaintext
> applies to every step here. This file is the rare-operation playbook; don't load it for
> routine secret access.

Use this when the master is compromised, on a periodic schedule, or when forking the
project. The procedure was developed and validated end-to-end in commits `d8ee863` (CLI +
atomicity), `e248092` (rotation), `dcee14b` (workflow encryption fix).

## Pre-flight checks

1. **Workflow trigger calendar.**
   `grep -nE 'schedule:|cron:' .github/workflows/artifacts-release-nightly.yaml`. Rotate
   during a quiet window so a scheduled run doesn't fire mid-rotation.
2. **`@secret:MASTER_PASSWORD` references.**
   `grep -rn 'MASTER_PASSWORD' conf-gen/ openwrt-builder/files/ .github/`. Confirm any
   references are intentional. The on-device crontab references it; that's acceptable
   because the OpenWRT image is itself GPG-encrypted with the same master, so no incremental
   exposure.
3. **Repo visibility.** `gh repo view <owner/repo> --json visibility`. Public repos require
   workflow-artifact encryption (already in place as of `dcee14b`); fingerprint hashes
   published to CI logs are world-readable, so the master input must be high-entropy (UUID
   v4).
4. **Old master is escrowed.** The user must already have the *current* master in a personal
   store (password manager, etc.) before starting — needed for rollback and to decrypt
   historical release artifacts.
5. **Workspace clean.** `git status` — no uncommitted changes that could end up bundled with
   the rotation commit.

## Sequence

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

## Why each step is the way it is

- **B0/B7 (disable/enable):** between B2 and B8, GitHub holds the new master while
  master-branch still has old-encrypted `secrets.yaml`. Any unrelated push or scheduled cron
  in that window would fail in `build_configuration`. Disabling the workflow collapses the
  race window to zero.
- **B1.5 (escrow before any destructive step):** if anything fails after B2, recovery
  requires the new master. After C1 the file is gone. Without escrow, the rotation is
  one-way with no rollback.
- **B3 (fingerprint comparison):** GitHub secrets are write-only. The 16-hex SHA-256 prefix
  is a fingerprint, safe for public CI logs given UUID v4 entropy. **Do not** publish a
  fingerprint of a non-UUID password — short or low-entropy inputs become brute-forceable
  from the prefix.
- **B4 stdin-only CLI:** `--new-password-stdin` pattern keeps the value off argv and out of
  `/proc/<pid>/cmdline`, shell history, audit logs. The CLI refuses an interactive TTY to
  avoid terminal echo. Strips one trailing `\n` (`gh secret set < file` also strips one —
  alignment depends on this).
- **B6 `[no release]`:** the deployed router still has the old master baked into its image.
  Without `[no release]`, the very next CI run publishes a new-master-encrypted release that
  the router cannot decrypt at `30 0 * * *`. Keep `[no release]` on every subsequent commit
  until the router is re-flashed.

## Recovery paths

| Failure | State on disk | Recovery |
|---|---|---|
| B3 fingerprint mismatch | GH secret possibly wrong | Re-run B2 |
| B4 raises before write | `secrets.yaml` untouched | Re-set GH to old: `gh secret set MASTER_PASSWORD --repo … <<<"$(pass show old-master)"`. Investigate, retry. |
| B5 fails (corrupt rotated file) | local `secrets.yaml` rotated, not yet pushed | `git checkout -- common/src/common/secrets.yaml`. Re-set GH to old. Abort. |
| B8 push fails | local rotated, GH has new master | Retry push promptly; window of broken CI is the duration |
| B9 CI fails | repo + GH consistent in theory | Re-trigger; if persistent, B3 was wrong |

## After rotation — outstanding work for the user

- **Re-flash the router** with a locally-built image using the new master from escrow. Use
  `bash openwrt-builder/build.sh` with `PASSWORD=$(pass show homelab/master-password)`.
- **Keep `[no release]` on subsequent commits** until the router is re-flashed.
- **Consider rotating non-master secrets** (`PPPOE_*`, `JP_NODE_*`, `NAIVE_PROXY_*`,
  `CLASH_*`, `SUBSCRIPTION_*`, `DOT_PUB`) at the upstream services — the master rotation
  doesn't invalidate them, and they may have been leaked via past unencrypted workflow
  artifacts.
- **Delete pre-rotation workflow artifacts** if they pre-date the encryption fix
  (`dcee14b`): `gh api -X DELETE /repos/<owner/repo>/actions/artifacts/<id>`.
- **Old GitHub Releases** remain encrypted with the old master; if you care, manually delete
  via `gh release delete-asset`.

## Rotation-specific footguns

- **`uuidgen -r` not `uuidgen`**: bare `uuidgen` may produce v1 (MAC-derived) UUIDs on
  BSD-derived platforms, dropping effective entropy from ~122 bits to ~60. Always `-r` for
  v4. (The fingerprint-prefix scheme in B3 *only* stays safe with v4 entropy.)
- **`gh secret set` strips one trailing `\n` from stdin.** If the local file has the newline
  and the rotation CLI doesn't strip it (or vice versa), the local secrets.yaml encryption
  diverges from GitHub's and CI fails. Both sides must be consistent — current
  implementation: file has no `\n` (`uuidgen | tr -d '\n'`), CLI strips one if present.
