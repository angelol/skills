# Security Review Skill

A portable adaptation of the security-review workflows in OpenAI's Codex Security plugin, packaged as a standard skill for coding agents.

It supports repository audits, Git diff reviews, deep multi-pass scans, threat modeling, finding validation, attack-path analysis, security fixes, vulnerability reports, hardening proposals, `SECURITY.md` policy work, and approval-gated issue tracking.

The Codex Security plugin is built specifically for Codex and integrates with Codex-native orchestration, MCP tools, workbench state, and UI. This skill offers roughly the same user-facing workflow coverage using ordinary Markdown and Python standard-library scripts, so it can work with any coding harness that supports skills. It has no MCP server, connector, UI form, hosted service, or agent-specific runtime dependency.

## Install

Clone or copy this repository into the skill directory used by your coding agent, preserving `SKILL.md` at the skill root:

```sh
git clone https://github.com/angelol/security-audit-skill.git security-review
```

If your agent does not support automatic skill discovery, point it at `SKILL.md` when requesting security work.

## Example requests

```text
Use the security-review skill to audit this repository.
Review the changes between main and HEAD for security regressions.
Run a deep, multi-pass security review of src/auth.
Validate this path-traversal finding against the current source.
Fix this confirmed authorization bypass and add regression coverage.
Create a threat model for this repository.
```

## What it preserves

- Exact target and scope boundaries.
- Repository-wide threat modeling with diff-focused review when appropriate.
- Separate discovery, validation, attack-path, severity, and reporting stages.
- Explicit counterevidence, proof gaps, candidate dispositions, and coverage.
- Stable finding identities and deterministic Markdown reports.
- Read-only scans and separately authorized fixes or external writes.
- Offline review by default.

## Portable helpers

The scripts are optional and require only Python 3.

Create and seal canonical review artifacts:

```sh
python3 scripts/security_review.py init \
  --target /path/to/repository \
  --output /tmp/security-review \
  --mode standard

python3 scripts/security_review.py validate --scan-dir /tmp/security-review
python3 scripts/security_review.py finalize --scan-dir /tmp/security-review
```

Build deterministic source inventories and resolve nested security policies:

```sh
python3 scripts/scope_tools.py inventory \
  --repo /path/to/repository \
  --output /tmp/security-review/inventory.jsonl \
  --mode standard

python3 scripts/scope_tools.py policy \
  --repo /path/to/repository \
  --scope src/component
```

Use `python` instead of `python3` when that is the configured interpreter, such as on some Windows systems. Git is optional for repository scans and required for diff inventories.

## Repository layout

```text
SKILL.md
references/
  adjacent-workflows.md
  artifact-contract.md
  evidence-pipeline.md
  review-modes.md
scripts/
  scope_tools.py
  security_review.py
```

`SKILL.md` routes each request and loads only the references needed for that workflow. The helper scripts create artifacts and inventories; they never decide whether code is vulnerable.

## Origin and relationship to Codex Security

This skill is based on the workflows and capabilities of OpenAI's Codex Security plugin. It preserves the plugin's evidence-led phase separation, conservative finding validation, attack-path and severity analysis, coverage accounting, remediation discipline, and adjacent security workflows in a portable skill format.

The implementation is an independent adaptation and does not include proprietary plugin source code. It intentionally replaces Codex-specific MCP calls, durable workbench orchestration, desktop progress UI, native forms, connector integrations, and token accounting with agent-neutral instructions and local filesystem artifacts. As a result, it aims for roughly equivalent functional coverage rather than exact runtime or UI parity with the Codex Security plugin.

## License

Apache License 2.0. See [LICENSE](LICENSE).
