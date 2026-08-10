# Adjacent security workflows

## Contents

- Triage supplied findings
- Fix a finding
- Vulnerability writeup
- Structural hardening
- Define or update SECURITY.md
- Track findings

## Triage supplied findings

Use triage for an existing scanner result, advisory, ticket, report, or finding collection. Do not broaden into repository discovery.

1. Normalize one item per supplied finding. Preserve source IDs, scanner text, affected version, location, rule, severity, evidence, and remediation exactly; record missing fields as proof gaps.
2. Resolve the current repository version and applicable security policy.
3. Locate the claimed construct and trace the static source/control/sink path.
4. Return one verdict per input:
   - `confirmed`: current source supports a real, in-scope security impact;
   - `not_actionable`: exact counterevidence shows it is absent, fixed, unreachable under the model, or not a security boundary;
   - `needs_review`: a decisive proof gap remains.
5. Rank `confirmed` and `needs_review` queues separately by exploitability: reachable unauthenticated paths first, then cross-tenant/authenticated, then internal/admin or configuration-dependent paths. Preserve source order as a tiebreaker.

Do not deduplicate inputs unless the user asks. Do not claim dynamic validation when only static triage was performed.

## Fix a finding

Modify code only after the user requests a fix. Establish the patch contract first:

- current vulnerable source-to-sink path and required preconditions;
- security invariant and narrowest complete enforcement boundary;
- supported legitimate behavior, API, compatibility, and error semantics;
- reproducer, tests, affected locations, nearby helpers, and repository conventions.

Classify the current state as `vulnerable`, `already_safe`, or `unproven`. Do not patch an adjacent weakness when the reported path cannot be shown.

Prefer a failing regression test or realistic reproducer before the fix. Include a malicious case and a legitimate control through the same boundary. Implement the smallest repository-native change that completely enforces the invariant; avoid unrelated refactors.

Verify in this order:

1. applicability, final diff scope, syntax, import, or buildability;
2. original malicious case no longer reproduces;
3. alternate bypass review through callers, branches, equivalent sinks, and another malicious input class when practical;
4. legitimate behavior, API, and error semantics remain;
5. focused tests, owning-package tests, formatter, linter, type checker, and relevant integration checks.

Report `fixed` only when every relevant gate passes. Report `no_change` when evidence proves the code is already safe. Otherwise report `blocked` with the exact missing proof or product decision.

## Vulnerability writeup

Treat the finding as a hypothesis. Establish exact source revision, assessed public release when available, attacker position, reachable entry point, expected behavior, actual failure, narrowest demonstrated impact, counterevidence, and reproduction status.

Never invent affected versions, release history, source excerpts, line numbers, CVEs, CVSS, PoC output, logs, or deployment prevalence. Distinguish inspected PoCs from executed PoCs and observations from predictions. Test only authorized local targets; use disposable targets for destructive or crashing cases.

Make each vulnerability self-contained with:

- summary and security boundary;
- affected software and verified version range or explicit unknowns;
- attacker prerequisites and step-by-step attack path;
- technical root cause with repository-relative source locations;
- reproduction or validation procedure with actual results clearly labeled;
- impact, likelihood, severity, counterevidence, and limitations;
- remediation and regression tests.

Use public release numbers in reader-facing prose when verified. Keep local absolute paths and private drafting provenance out of distributable reports.

## Structural hardening

Use hardening only when the user asks for systemic improvements or when several findings plausibly share a structural condition. Do not manufacture an architecture project when tactical fixes are proportionate.

1. Verify findings and source evidence; separate observed, inferred, and proposed claims.
2. Group recurring broken controls, duplicated policy, ambient authority, lifecycle confusion, weak isolation, or fail-open containment into opportunities.
3. State falsifiable desired invariants, non-goals, compatibility obligations, resource limits, and rollout constraints.
4. Develop the baseline plus two or three genuinely different options when warranted: centralized owned APIs, capabilities/scoped handles, privilege or process separation, safer representations/state machines, or central policy with local enforcement.
5. Compare security effect, residual risk, performance, memory, reliability, operations, compatibility, migration, developer ergonomics, reversibility, and validation plan. Label measurements as measured, source-derived, analogous, or hypothetical.
6. Map every finding to addressed, mitigated, unaffected, or unknown for each option. State whether tactical patches remain necessary.
7. Recommend under explicit assumptions and state what would change the recommendation. Do not implement until the user selects an option and asks for it.

## Define or update SECURITY.md

Inventory root and nested `SECURITY.md` files. Compose guidance from root to leaf and let the closest file win. Do not treat `.github/SECURITY.md` or a disclosure policy as repository-wide scanner guidance unless its content actually defines code-review boundaries.

Establish system scope, exposure, assets, attacker-controlled inputs, trust boundaries, invariants, reportability, severity context, exclusions, accepted risks, limitations, and compensating controls from source and owner-confirmed facts. Mark unresolved decisions; never turn an inference into suppression authority.

For an edit, show the exact target and diff first. Obtain explicit approval before introducing exclusions, accepted risk, severity changes, or sensitive details. Re-read the file immediately before writing and re-preview if it changed.

## Track findings

Treat tracking as an external write, separate from scanning. Use the provider tools, CLI, or API available to the current agent; do not require a particular connector.

1. Validate the canonical finding source and require an exact user-selected finding or batch.
2. Resolve one provider, identity, private-by-default destination, and audience. Never silently switch accounts, transports, projects, repositories, or providers.
3. Search the exact destination for duplicates using finding ID/fingerprint first and semantic root-cause terms second.
4. Preview every exact title, body, metadata field, visibility warning, and create/update/reuse decision. Obtain explicit approval.
5. Recheck source, identity, destination, visibility, and duplicates after approval.
6. Execute serially. Do not retry an uncertain create; search/read back first.
7. Read every created, updated, or reused item back through the same identity and transport before claiming success.

Default sensitive content to private destinations. Do not place exploit details, secrets, private links, or unverified claims in public trackers. Do not stage, commit, push, publish an advisory, or disclose a vulnerability unless the user separately authorizes that action.
