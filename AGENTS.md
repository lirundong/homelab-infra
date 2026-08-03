# AGENTS.md — Homelab Infrastructure Monorepo

Canonical instructions for every coding agent. `CLAUDE.md` links here; agent-specific
directories remain separate for sandbox settings, while skills are shared from `.ai/skills`.

## Instruction Map

Before changing a scoped path, read its closest `AGENTS.md` in addition to this file:

- `.github/` → `.github/AGENTS.md`
- `common/` → `common/AGENTS.md`
- `conf-gen/` → `conf-gen/AGENTS.md`
- `conf-cookbook/` → `conf-cookbook/AGENTS.md`
- `openwrt-builder/` → `openwrt-builder/AGENTS.md`
- `util-cookbook/` → `util-cookbook/AGENTS.md`
- `util-cookbook/tencent-cloud/` → also read its local `AGENTS.md`
- root `Dockerfile` → `util-cookbook/tencent-cloud/AGENTS.md`

This explicit routing matters for agents started at the repository root: nested instructions
are not necessarily loaded later merely because a file is touched.

## Repository Structure

Python >=3.12 uv workspace; `uv.lock` is pinned. `uv sync` installs `common`, `conf-gen`, and
`tencent-cloud` editably.

- `conf-gen`: generate Clash, Quantumult-X, and sing-box configurations
- `common`: encrypted secrets and template expansion
- `openwrt-builder`: build custom OpenWRT images
- `conf-cookbook`: reference service configurations
- `util-cookbook`: standalone utilities, including the `tencent-cloud` DDNS package

## Shared Commands

```bash
uv sync
uv sync --extra dev
uv run --extra dev pre-commit install
uv run --extra dev pre-commit run --all-files
uv run --extra dev mypy common/src/common conf-gen/src/conf_gen \
    util-cookbook/tencent-cloud/src/tencent_cloud
```

`pre-commit` is a root `dev`-extra dependency; always invoke it through
`uv run --extra dev`. Install the hook in each checkout and use ordinary `git commit`.

The configured hooks run whitespace/EOF, YAML/TOML/JSON, merge-conflict, debug-statement,
large-file, Black, isort, and mypy checks. They do not run pytest, builds, ShellCheck, or
shfmt; use each component's `AGENTS.md` for additional validation.

## Workflow

For non-trivial changes:

1. Branch from `master` as `<username>/<feature, fix, chore, ...>/<description>`.
2. Run all pre-commit hooks and the affected component's tests or end-to-end command.
3. Push and create a PR with `gh pr create`.
4. Watch CI with `gh run watch <id>`; `ci_gate` is the single required check.
5. Rebase-merge only after `ci_gate` passes.

Commit messages use `[scope] imperative summary`, for example
`[conf-gen] drop HTTPS DNS queries`.

### Agent attribution on GitHub

When Codex running an OpenAI model authors or substantially edits GitHub prose through the
user's identity, append this after a blank line:

```markdown
— [OpenAI Codex](https://github.com/openai/codex)
```

Do not use `@codex` as a passive signature; GitHub mentions trigger Codex cloud tasks.

## Shared Conventions

- Python uses Black (`line-length=99`), isort (`profile=black`, single imports), package-local
  mypy settings, and PEP 561 `py.typed` markers.
- Fail fast on invariants: do not hide unexpected failures with `|| true`, `2>/dev/null`, or
  `try`/`except`/`pass`.
- Prefer in-place edits over file reconstruction and symlinks over moving tool-owned files.
- Keep source comments pithy; put extended rationale in the PR description or commit body.
