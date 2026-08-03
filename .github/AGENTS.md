# GitHub Workflows

Applies to `.github/`; inherit the repository-root instructions.

## CI and Releases

`artifacts-release-nightly.yaml` detects changed paths, then conditionally runs:

1. `type_check`
2. `conf_gen_tests` and `build_configuration`
3. `build_openwrt`
4. `ci_gate`
5. release jobs on nightly or `master`

OpenWRT builds cover `x86/64` and `rockchip/armv8`
(`friendlyarm_nanopi-r6s`) with:

- stable `25.12.5`: GCC `14.3.0_musl`, required
- `snapshots`: GCC `14.4.0_musl`, allowed to fail

`ci_gate` is the single branch-protection check and fans in only jobs required by the event
and touched paths. Release jobs depend on it. Non-`master` pushes skip CI when the branch
already has an open PR, making the PR run authoritative.

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
