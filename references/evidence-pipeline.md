# Evidence pipeline

## Contents

- Threat map
- Discovery
- Validation
- Attack path
- Severity and confidence
- Common candidate families

## Threat map

Build a practical, repository-scoped model from source and deployment evidence:

- what the software does and which product surfaces run in real workflows;
- actors and attacker capabilities;
- assets, privileges, secrets, protected state, and availability requirements;
- entry points and attacker-controlled inputs;
- trust boundaries between users, tenants, processes, services, plugins, hosts, and networks;
- sensitive operations and expected controls;
- security objectives, assumptions, and invariants.

Preserve a supplied threat model verbatim and use it as the source of truth. Otherwise write a concise model that separates observed facts from assumptions. Do not turn a threat model into a list of findings.

## Discovery

Start from source-backed questions and trace actual callers, transformations, controls, and sinks. Record a candidate only when it has:

- a plausible attacker or cross-boundary input;
- an entry point or caller path;
- an expected security control;
- the suspected broken or missing control;
- a sensitive operation or protected asset;
- precise source locations;
- a concrete security impact hypothesis.

Keep different root causes separate. Keep independently reachable vulnerable instances separate even when they share a CWE. Group only when one broken control and one remediation truly close every instance.

Treat shared wrappers as reachability evidence, not a reason to erase concrete sinks. For repeated operation families, enumerate the request-selectable operations, branches, codecs, parser variants, routes, or call sites that make the broad claim true.

Do not promote comments, tests, names, dangerous API use, or missing best practices alone. They are leads until the source/control/sink path is established.

## Validation

Create a short rubric for each candidate, covering at most five decisive claims. Identify the attacker input, boundary, control, sink, preconditions, and impact before choosing a method.

Prefer the strongest proportionate method:

1. focused regression or unit/integration test through the real boundary;
2. realistic local interface reproduction through HTTP, CLI, RPC, parser, plugin, message, or package API;
3. crashing PoC, sanitizer, valgrind, or non-interactive debugger trace for memory-safety, parser, or denial-of-service claims;
4. complete static assessment when runtime setup is unavailable or disproportionate.

A static assessment must trace source, transformations, closest control, sink, caller reachability, boundary evidence, prerequisites, impact, existing mitigations, strongest counterevidence, and exact proof gaps. Use existing tests and deployment/configuration evidence as supporting facts. Missing internal services, credentials, or dependencies do not disprove the path.

Assign one disposition:

- `reportable`: evidence supports a real vulnerability within scope;
- `suppressed`: source-backed counterevidence defeats the claimed path or impact;
- `not_applicable`: the candidate does not apply to this code, version, or surface;
- `deferred`: a material proof gap remains and bounded work cannot resolve it.

Calibrate confidence from the validation method and evidence, not from the vulnerability class. Record what was attempted and what remains unknown. Keep PoCs and logs outside the target tree unless repository changes were authorized.

## Attack path

For every reportable or deferred candidate, record:

1. attacker and required access;
2. exposed entry point or plausible caller;
3. attacker-controlled value or state;
4. transformations and trust-boundary crossings;
5. expected and actual controls;
6. sensitive sink or protected action;
7. prerequisites and limiting conditions;
8. concrete confidentiality, integrity, availability, or privilege impact;
9. strongest counterevidence and why it does or does not defeat the path;
10. likelihood, impact, severity, confidence, and final decision.

Keep facts, severity calibration, and policy adjustment separate. Do not invent an attack chain. Missing public-ingress evidence lowers confidence when relevant but does not automatically suppress a library, parser, tenant, internal, or privileged boundary that is in the threat model.

## Severity and confidence

Rate impact and likelihood independently as `high`, `medium`, `low`, or `unknown`.

- Use `critical` only for a clearly reachable, immediately actionable path to severe compromise at meaningful scale.
- Use `high` for high-impact, high-likelihood compromise.
- Use `medium` for high impact with medium or unknown likelihood, or medium impact with high likelihood.
- Use `low` for high impact with low likelihood, medium impact with less than high likelihood, or low impact.
- Use `unknown` only while a deferred proof gap prevents calibration; do not place unknown severity in final reportable findings.

Downgrade paths requiring same-tenant, localhost, internal, administrative, or unusually constrained access when those constraints reduce the boundary crossed or realistic impact. Ignore self-only or already-privileged behavior without a meaningful privilege gain.

Rate confidence separately:

- `high`: direct source trace plus successful realistic reproduction or equivalently decisive proof;
- `medium`: complete source/control/sink trace with plausible reachability but limited runtime proof or deployment evidence;
- `low`: material assumptions remain, but the candidate is specific enough to preserve or defer.

## Common candidate families

Use these as prompts, never as a checklist that proves coverage:

- authentication, authorization, IDOR, tenant/ownership isolation, session and lifecycle state;
- SQL/NoSQL/LDAP/XPath injection, command/code injection, template execution, unsafe code generation;
- XSS, redirects, header injection, request smuggling, prototype pollution;
- path traversal, archive extraction, uploads, static resources, import/export, symlink and hardlink handling;
- SSRF, callbacks, webhooks, redirect following, credential-bearing requests;
- unsafe deserialization, XML entities, parser confusion, type resolution, object construction;
- hardcoded credentials, secret exposure, insecure cryptography or trust configuration;
- memory corruption, algorithmic complexity, unbounded allocation, recursion, concurrency, and resource exhaustion;
- sandbox, plugin, native binding, capability, and process-boundary escapes;
- security misconfiguration and fail-open error handling.
