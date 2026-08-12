# Skills

A collection of reusable skills for coding agents. Each skill lives in its own self-contained directory and can be installed independently.

## Available skills

| Skill | Description |
|---|---|
| [`crown-decision`](crown-decision) | Runs an adversarial multi-agent tournament of advocates, critics, and jurors to crown consequential architecture, engineering, product, protocol, security, or operational decisions. |
| [`security-review`](security-review) | Performs evidence-led security reviews, including repository and diff scans, threat modeling, finding validation, attack-path analysis, fixes, hardening, and reporting. |

## Install

Give your coding agent the directory URL for the skill you want:

```text
Install this skill: https://github.com/angelol/skills/tree/main/crown-decision
```

Or clone the collection and copy an individual skill into your agent's skills directory:

```sh
git clone https://github.com/angelol/skills.git
cp -R skills/crown-decision /path/to/your-agent/skills/crown-decision
```

Each directory's `SKILL.md` is the entry point. Supporting `references/`, `scripts/`, `agents/`, or `assets/` directories belong to that skill and should be installed with it.

## License

Apache License 2.0. See [LICENSE](LICENSE).

`security-review` is a portable adaptation of workflows from OpenAI's [Codex Security](https://github.com/openai/codex-security) project.
