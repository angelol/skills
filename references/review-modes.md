# Review modes

## Contents

- Standard scan
- Diff scan
- Deep scan
- Shared preflight
- Coverage closure

## Standard scan

Use one independent general audit plus a threat-map-driven review of the requested repository or path.

1. Inventory source-like files and the primary runnable, exposed, privileged, parsing, persistence, filesystem, network, and execution surfaces.
2. Perform a baseline audit without seeding it with the coordinator's favorite hypotheses. If delegation is available and authorized, assign the baseline to an independent reviewer. Otherwise run it sequentially with a fresh perspective and disclose that independence was limited.
3. Build investigation packets around a shared attacker, protected asset, entry points, expected control, sensitive operations, and concrete source anchors.
4. Review packets using forward tracing, backward tracing, authorization/business-logic analysis, and open-ended source inspection as useful. Do not force a fixed reviewer count.
5. Combine observations only when they share the same broken control and effective remediation. Preserve every independently reachable route, sink, operation, and affected location.
6. Run one centralized validation and attack-path pass over the deduplicated candidates.

Treat supporting files outside a scoped path as context only. Report a finding only when an affected entry point, control, operation, or sink remains in scope.

## Diff scan

Resolve the exact Git comparison before review:

- PR or branch: merge base to head;
- commit: parent or explicit base to commit;
- range: explicit base to head;
- working tree: base revision to staged and unstaged changes, including untracked files when requested.

Use local Git commands that do not modify the worktree. Record the base, head, and dirty state. Review every changed source-like file; do not rank changed files out of scope because they look low risk.

Keep discovery anchored to changed behavior and the minimum supporting code needed to understand it. Expand to unchanged siblings only when the diff:

- changes a shared guard, sink, parser, serializer, template, query builder, filesystem/network helper, route pattern, or security configuration they use;
- newly exposes or reaches them; or
- creates the same independently reachable vulnerable pattern in several call sites.

Use unchanged siblings as negative controls. Do not report unrelated pre-existing weaknesses unless the user asks for a wider review. Keep a changed wrapper and its underlying shared control or sink both addressable.

Generate the repository-wide threat model before diff-centered discovery unless the user supplied an authoritative model or explicitly requested a narrower one. Do not let the touched subsystem distort the repository's overall attacker model.

## Deep scan

Use deep mode only when the user asks for exhaustive, repeated, multi-pass, or variance-reducing review. Deep mode increases time and compute.

1. Freeze target, scope, policy, threat context, and source inventory.
2. Run multiple discovery passes with materially different perspectives or partitions. Keep each pass independent of earlier conclusions when practical.
3. Normalize every pass into one candidate ledger. Preserve exact instances and provenance; do not use recurrence as validation.
4. Continue until the requested cap is reached or two consecutive complete passes add no new root cause, vulnerable instance, or unresolved high-risk surface. State the chosen stopping rule.
5. Synthesize one conservative threat model from the passes.
6. Run validation once over the canonical candidate set.
7. Run attack-path analysis once over the surviving or deferred candidates.
8. Finalize one report and one coverage record. Do not publish per-pass findings as final results.

If delegation is unavailable, simulate independence sequentially by changing perspective and withholding earlier candidate conclusions until each discovery pass completes. Report this limitation.

## Shared preflight

Before substantive review, verify:

- target resolves to the intended regular directory and requested paths remain inside it;
- Git revisions and diff are resolvable for diff mode;
- applicable repository instructions and root/nested `SECURITY.md` policies are known;
- one offline search command works (`rg`, then `git grep`, then `grep`/`find`);
- language, build, test, sanitizer, debugger, or package tools needed for likely validation are locally available;
- output is outside the target tree or explicitly approved;
- repository state is recorded so unrelated user changes are preserved;
- network access, external systems, credentials, and destructive tests remain disabled unless explicitly authorized.

Prefer `scripts/scope_tools.py inventory` for a deterministic source-like inventory and `scripts/scope_tools.py policy` for safe root-to-leaf policy resolution. Review excluded generated/vendor directories separately only when they are explicitly in scope or implement shipped security-sensitive behavior.

Continue with degraded capabilities when safe. Record warnings and their effect on confidence or coverage. Stop only when the target, scope, or safe execution boundary cannot be established.

## Coverage closure

Track coverage by meaningful surface, not by a vague claim that the repository was inspected. Useful surfaces include:

- public APIs, handlers, RPC, CLI, protocol and parser entry points;
- authentication, authorization, session, ownership, tenant, and lifecycle transitions;
- database queries and state mutation;
- filesystem paths, uploads, archives, imports, exports, and resource serving;
- outbound requests, callbacks, redirects, and credential-bearing clients;
- deserialization, templates, code generation, interpreters, compilers, plugins, native bindings, and process execution;
- secrets, cryptography, trust stores, security configuration, and deployment boundaries;
- resource exhaustion, concurrency, memory safety, and failure containment.

Give each surface one disposition: `reviewed`, `reported`, `no_finding`, `not_applicable`, or `deferred`. A surface is closed only when the relevant files and candidate questions have explicit outcomes. Mark the scan `partial` if a material surface is deferred, the inventory is incomplete, or validation gaps prevent closure.
