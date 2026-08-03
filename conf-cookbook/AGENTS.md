# conf-cookbook

Reference configurations for Docker, Nginx, Shadowsocks-Rust, and V2Ray. Inherit the
repository-root instructions.

These files are deployment examples, not generated `conf-gen` output. Preserve each
service's native format and keep environment-specific values out of tracked plaintext.

There is no automated test, schema-validation, or formatting suite for this directory.
Validate changed files with the corresponding upstream tool when available; repository
pre-commit provides only generic JSON/YAML and file-hygiene checks here.
