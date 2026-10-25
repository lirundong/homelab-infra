# GitHub Workflows

Applies to `.github/`; inherit the repository-root instructions.

## CI and Releases

`artifacts-release-nightly.yaml` detects changed paths, then conditionally runs:

1. `build_configuration`
2. `build_openwrt`
3. `ci_gate`
4. release jobs on nightly or `master`

PR path routing skips Markdown and `docs/` paths. Changes under `conf-gen/` require
configuration generation; `openwrt-builder/` or `util-cookbook/tencent-cloud/` require firmware
builds. Changes under `common/`, root dependency manifests, or workflows require both.
Unrelated changes pass the gate without generation or builds. Formatting and type checks
remain local pre-commit hooks.

Configuration generation succeeds when the CLI exits successfully; CI does not run schema,
client configuration checks, or runtime probes. Firmware-only PRs use the published daemon
configuration; when generation also runs, firmware uses that run's configuration artifact.

OpenWRT builds cover `x86/64` and `rockchip/armv8`
(`friendlyarm_nanopi-r6s`) with:

- stable `25.12.5`: GCC `14.3.0_musl`, required
- `snapshots`: GCC `14.4.0_musl`, scheduled nightly only, allowed to fail

`ci_gate` is the single branch-protection check and fans in only jobs required by the event
and touched paths. Release jobs depend on it. `push` triggers only on `master`; feature
branches get CI solely from their PR run.

## Secret-bearing Artifacts

Read `.ai/skills/secret-handling/SKILL.md` before editing workflows that use
`MASTER_PASSWORD`; also read its `references/artifact-encryption.md` when changing artifact
handling.

Generated configurations and OpenWRT images contain expanded secrets. Encrypt them before
`actions/upload-artifact`; decrypt only at the consumer. Keep encrypted workflow artifacts
at seven-day retention.

`verify-master-password.yaml` is owner-gated, workflow-dispatch only, has `permissions: {}`,
and emits only a 16-hex SHA-256 prefix for rotation comparison.

## Validation

Run all repository pre-commit hooks. Review event/path conditions and job dependencies
against `ci_gate`; workflow changes affecting configurations or firmware require the
corresponding end-to-end CI jobs, not YAML syntax alone.
