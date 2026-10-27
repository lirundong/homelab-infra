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
6. **`.env.local` holds the current master.** The user creates it out-of-band (see
   [../SKILL.md](../SKILL.md)); agents never read it. Run the whole sequence in one shell with
   `PASSWORD` *not* exported — an inherited `PASSWORD` silently overrides every `--env-file`.

## Sequence

```bash
# B0 — close the race window
gh workflow disable artifacts-release-nightly.yaml --repo <owner/repo>

# B1 — generate the new master into a private temp dir (portable to macOS and Linux)
umask 077 && ROT="$(mktemp -d)"
uv run python3 -c 'import sys, uuid; sys.stdout.write(str(uuid.uuid4()))' > "$ROT/master-new"
{ printf 'PASSWORD='; cat "$ROT/master-new"; } > "$ROT/new.env"
# Sanity: 36 bytes, UUID version (15th char) == '4'
test "$(wc -c < "$ROT/master-new")" -eq 36
test "$(cut -c15 "$ROT/master-new")" = 4

# B1.5 — USER escrows the new master out-of-band (separate terminal, not Claude)
#   pass insert -m homelab/master-password < "$ROT/master-new"
#   diff <(pass show homelab/master-password) "$ROT/master-new"
# Pause until the user confirms escrow succeeded. After C1 the file is gone
# and the master is recoverable only from this escrow.

# B2 — upload to GitHub via stdin (value never on argv or stdout)
gh secret set MASTER_PASSWORD --repo <owner/repo> < "$ROT/master-new"

# B3 — verify GitHub-side bytes match local-side via 16-hex sha256 fingerprint
gh workflow run verify-master-password.yaml --repo <owner/repo>
# Wait for the run to complete, fetch the log, extract the 16-hex line.
# Compare to: sha256sum < "$ROT/master-new" | cut -c1-16
# Mismatch → re-run B2.

# B4 — rotate local secrets.yaml; .env.local still holds the old master
uv run --env-file .env.local common-rotate-password < "$ROT/master-new"
# Decrypts every entry with old fernet, derives new fernet, re-encrypts,
# atomically swaps via temp + flush + fsync + chmod-preserve + os.replace
# + dir-fsync. See _manager.py:rotate_password.

# B5 — fresh-process round-trip; boolean only
uv run --env-file "$ROT/new.env" python3 -c '
from common import secrets
import sys
ok = sum(1 for k in secrets._encrypted_secrets if getattr(secrets, k))
sys.exit(0 if ok == len(secrets._encrypted_secrets) else 1)'

# B6 — commit
git add common/src/common/secrets.yaml
git commit -m "[common] rotate secrets.yaml master password"

# B7 — re-enable workflow
gh workflow enable artifacts-release-nightly.yaml --repo <owner/repo>

# B8 — push (triggers CI on the new tip; build_configuration is the integration test)
git push origin master

# B9 — watch CI; on success it publishes releases encrypted with the new master
gh run watch <run-id>

# B10 — USER updates the router before its next 00:30 config fetch (see below)

# B11 — make the new master the local default
mv "$ROT/new.env" .env.local

# C1 — clean up
rm -rf "$ROT"
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
- **B4/B5 `--env-file`:** both masters reach the process from files, never from argv or a
  command substitution. uv does not override an already-exported `PASSWORD`, hence the
  pre-flight check.
- **B4 stdin-only CLI:** the new master arrives on stdin, keeping it off argv and out of
  `/proc/<pid>/cmdline`, shell history, audit logs. The CLI refuses an interactive TTY to
  avoid terminal echo. Strips trailing `\n` (`gh secret set < file` also strips one —
  alignment depends on this).
- **B10 router update:** CI has no release-skip switch, so every push to `master` publishes
  new-master artifacts, while the router's `/etc/crontabs/root` still holds the old master
  and fails to decrypt them at `30 0 * * *`. Right after B9, either flash the image B9
  released (decrypt it with the new master) or, in the user's own SSH session, replace the
  passphrase in both crontab lines.

## Recovery paths

| Failure | State on disk | Recovery |
|---|---|---|
| B3 fingerprint mismatch | GH secret possibly wrong | Re-run B2 |
| B4 raises before write | `secrets.yaml` untouched | Re-set GH to old: `pass show old-master \| gh secret set MASTER_PASSWORD --repo …`. Investigate, retry. |
| B5 fails (corrupt rotated file) | local `secrets.yaml` rotated, not yet pushed | `git checkout -- common/src/common/secrets.yaml`. Re-set GH to old. Abort. |
| B8 push fails | local rotated, GH has new master | Retry push promptly; window of broken CI is the duration |
| B9 CI fails | repo + GH consistent in theory | Re-trigger; if persistent, B3 was wrong |

## After rotation — outstanding work for the user

- **Re-flash the router** with a released image if B10 only patched its crontab, so the
  baked-in master matches again after a factory reset.
- **Consider rotating non-master secrets** (`PPPOE_*`, `JP_NODE_*`, `NAIVE_PROXY_*`,
  `CLASH_*`, `SUBSCRIPTION_*`, `DOT_PUB`) at the upstream services — the master rotation
  doesn't invalidate them, and they may have been leaked via past unencrypted workflow
  artifacts.
- **Delete pre-rotation workflow artifacts** if they pre-date the encryption fix
  (`dcee14b`): `gh api -X DELETE /repos/<owner/repo>/actions/artifacts/<id>`.
- **Old GitHub Releases** remain encrypted with the old master; if you care, manually delete
  via `gh release delete-asset`.

## Rotation-specific footguns

- **Python `uuid.uuid4()`, not `uuidgen`**: macOS `uuidgen` has no `-r`, and util-linux
  `uuidgen` may fall back to time-based v1 UUIDs, dropping effective entropy from ~122 bits
  to ~60. (The fingerprint-prefix scheme in B3 *only* stays safe with v4 entropy.)
- **No `/dev/shm` on macOS**: B1 uses a `mktemp -d` directory under the per-user `$TMPDIR`
  instead. It is disk-backed, so rely on FileVault (or full-disk encryption on Linux) and
  remove it in C1.
- **`gh secret set` strips one trailing `\n` from stdin.** If the local file has the newline
  and the rotation CLI doesn't strip it (or vice versa), the local secrets.yaml encryption
  diverges from GitHub's and CI fails. Both sides must be consistent — current
  implementation: file has no `\n` (B1 writes without one), CLI strips any if present.
