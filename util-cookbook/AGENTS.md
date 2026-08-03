# util-cookbook

Standalone homelab utilities. Inherit the repository-root instructions.

`fetch_config.sh` retrieves released configurations; `asus-merlin/` contains LED scheduling
scripts. `tencent-cloud/` is a uv workspace package with its own `AGENTS.md`; read it before
changing that subtree.

`fetch_config.sh` decrypts downloaded configurations into its destination. Read
`.ai/skills/secret-handling/SKILL.md` before running or changing it, and never expose its
password or decrypted output.

There is no automated test, ShellCheck, or shfmt suite for the standalone shell utilities.
Preserve fail-fast behavior and validate changed scripts with `bash -n` or `sh -n` according
to their shebang, plus a safe non-destructive invocation where practical.
