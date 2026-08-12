---
name: crown-decision
description: Run a structured, adversarial multi-agent tournament to choose among competing architecture, engineering, product, protocol, security, or operational options. Use when the user explicitly asks to run a crowning workflow, crown a design through multiple agents, adjudicate plausible approaches with independent advocates, critics, and jurors, or continue an already-requested multi-agent review that has reached an unresolved consequential decision. Do not use for ordinary recommendations, trivial choices, or decisions the user has already fixed.
---

# Crown Decision

Use independent proposal, criticism, and jury rounds to reach one evidence-backed ruling. Optimize for the strongest decision under the user's declared constraints, not for consensus or vote count.

Read [references/prompts.md](references/prompts.md) before launching agents. Use its prompt templates to keep finalist definitions and evaluation criteria stable across rounds.

## Guardrails

- Treat prior user rulings as binding constraints. Reopen one only when new evidence directly invalidates its premise, and say so explicitly.
- Inspect enough primary evidence to frame the decision before delegating. Ask the user only for a missing choice that materially changes the tournament.
- Apply any relevant domain skill before framing the ruling. The primary agent must read skill instructions itself; do not delegate that responsibility.
- Keep agents independent within a round. When supported, spawn them with isolated or minimal history and provide a sanitized ruling card and evidence packet. Do not give an advocate other advocates' conclusions.
- Keep agents read-only unless the user separately authorizes implementation. Pin the evidence baseline before round one: revision or document version, dirty state, relevant configuration and platform versions, and date when time-sensitive.
- Instruct agents not to spawn subagents unless explicitly assigned as an orchestrator. Keep the tree bounded and legible.
- Prefer primary evidence: source code, tests, specifications, deployed configuration, official documentation, and measured behavior.
- Separate facts, inferences, preferences, and unknowns. Do not let a popular but unverified premise survive into the jury.
- Never manufacture certainty. Crown conditionally or require a decisive experiment when evidence cannot distinguish the finalists.
- Do not implement the crowned option unless the user also asks for implementation.

## Scale the Tournament

Choose the smallest tier proportionate to the decision:

| Tier | Advocates | Critics | Jurors | Use |
|---|---:|---:|---:|---|
| Compact | 3 | 2 | 3 | Narrow, reversible decision |
| Standard | 5 | 4 | 3 | Default architecture ruling |
| Deep | 7 | 5 | 4 | Irreversible mainnet or consensus change, severe adversarial exposure, or costly migration with uncertain evidence |

Treat these counts as completed independent reports, not merely spawned agents. Honor any user-specified minimum. Exceed 16 agents only when the user explicitly requests it. Reuse an advocate only to clarify, correct, or strengthen its own proposal. Use fresh agents for comparative critics and jurors. Never treat an absent report as support for another option.

## Workflow

### 1. Write the ruling card

State:

- the exact decision to make;
- the options already in scope, if any;
- binding prior rulings and non-goals;
- system facts and evidence locations;
- threat and trust boundaries;
- evaluation criteria in priority order;
- unknowns that could reverse the decision;
- deployment horizon and reversibility.

Separate the user-declared adversary model from trust introduced by each candidate. Treat unsettled trust as an unknown, not a binding premise. Identify independent decision axes and their dependencies. Crown separable axes one at a time; otherwise compare complete coherent bundles.

Give every agent the same ruling card. Do not encode the preferred answer in it.

### 2. Run independent advocates

Assign at least one advocate to steelman each materially distinct option already in scope. Use remaining advocates for cross-cutting lenses and, when capacity permits, one materially different candidate. Select lenses relevant to the domain, such as:

- semantic or protocol correctness;
- minimal PR scope and maintainability;
- security and adversarial behavior;
- operations, recovery, migration, and observability;
- performance, contention, and capacity;
- compatibility and upgrade safety;
- distributed-systems invariants;
- product semantics and user expectations;
- a fresh-ideas role tasked with finding an option outside the initial set.

Require each advocate to propose a concrete design, enumerate invariants and failure cases, rank alternatives, identify disqualifying evidence, and cite inspected evidence. Ask for a recommendation, not a survey.

### 3. Normalize finalists

After the advocate round:

1. Merge equivalent proposals.
2. Give each surviving candidate a stable name and exact definition.
3. Record any variants separately when they change stakeholders, trust, lifecycle, or guarantees.
4. Eliminate dominated candidates with a short reason.
5. Build a compact comparison matrix across the ruling criteria.

Define each finalist with actors, lifecycle, authorization, invariants, non-guarantees, failures, retries, recovery, migration, operating bounds, and introduced trust. Record evidence provenance and confidence. Eliminate a candidate as dominated only when dominance holds across every hard constraint and declared criterion.

Do not send critics ambiguous labels such as “A” without the full candidate definition. If a critic invents a material hybrid, normalize it as a new finalist and subject it to comparable criticism before the jury.

### 4. Run comparative critics

Give every critic the exact finalists and the strongest evidence from round one. Assign different comparison duties:

- correctness and invariant proof;
- adversarial red team;
- scope, complexity, and upgrade cost;
- operations, recovery, and incident handling;
- dissent: attempt to overturn the emerging favorite.

Require a total ranking, the strongest counterexample against each finalist, explicit kill criteria, and the smallest experiment that could reverse the ranking. Test the kill criteria before convening the jury; disqualify any candidate whose criterion is already met.

### 5. Correct poisoned premises

When new evidence changes a shared assumption:

1. Verify it against primary evidence.
2. State the correction to the user promptly.
3. Classify it as disproven, unverified, or inapplicable to the pinned environment.
4. Audit which proposals, eliminations, comparisons, and verdicts depend on it.
5. Broadcast the same correction to affected live agents.
6. Return to the earliest contaminated stage. Discard conclusions based on disproven claims; make unverified claims conditional or resolve them with an experiment.

Examples include unsupported platform primitives, incorrect authorization semantics, hidden deployment constraints, or an assumed invariant disproved by a test.

### 6. Convene a fresh jury

Use at least three independent jurors for Standard and Deep tiers:

- delivery juror: smallest complete, maintainable, shippable decision;
- security/reliability juror: trust boundary, abuse, liveness, and recovery;
- dissent juror: strongest attempt to overturn the likely crown.

Add domain, product, or operations jurors when those semantics are decisive. Give jurors the exact finalists, verified corrections, evidence matrix, and binding constraints. Do not anchor them with preliminary vote totals.

Keep all jurors except the dissent juror blind to the apparent favorite, advocate identities, rankings, and vote totals. Require each juror to inspect primary evidence behind any premise decisive to its verdict; the matrix is an index, not an authority.

Require each juror to select one crown, declare a conditional tie, or return no crown when every finalist violates a hard invariant. A valid verdict must include assumptions, non-negotiable safeguards, objective adoption gates, and a trigger for revisiting the ruling.

### 7. Crown by argument, not vote

Synthesize the verdict yourself. A majority is supporting evidence, not the decision rule. Prefer the option that:

1. satisfies every hard invariant;
2. survives the stated adversary and recovery model;
3. avoids unresolved protocol or migration holes;
4. is the smallest complete design under those constraints;
5. has objective tests that can falsify its assumptions.

If a more elaborate option protects against an actor already outside the trust boundary, label it as a conditional hardening path rather than automatically crowning it.

Before finalizing, verify that the crown has no active kill criterion, every hard invariant was evaluated, decisive unknowns are resolved or explicit conditions, and the dissent juror's strongest surviving objection is answered. Return no crown with the needed reframing or experiment if no candidate clears that bar.

### 8. Deliver the ruling

Lead with the crown. Include only the material reasoning:

- exact crowned design;
- why it beat the runners-up;
- declared trust boundary and assumptions;
- non-negotiable implementation rules;
- adoption gates, including merge, rollout, or decisive experiment gates when applicable;
- kill criteria and conditions that promote a runner-up;
- intentionally deferred follow-ups.

Keep the final self-contained. Avoid a transcript of every agent's opinion.

## Operating Rhythm

- Tell the user when the tournament starts, when finalists emerge, when a premise changes, and when the jury convenes.
- Wait in bounded intervals. Replace a stalled agent only when its assigned option or lens would otherwise be uncovered. Stop redundant branches and record missing evidence rather than inventing a verdict.
- Stop further fanout when another report has no credible information gain.
- Preserve agent reports long enough to audit the synthesis, but do not dump them into the final answer.
- For a sequence of user rulings, crown one decision at a time and carry the resulting constraints into the next ruling card.

## Completion Standard

Do not call the workflow complete until the promised role minimums have returned and the ruling has:

- one exact crown, an explicitly conditional outcome, or a justified no-crown result;
- no unresolved contradiction in its core invariants;
- an explicit trust boundary;
- concrete adoption gates;
- no active kill criterion on the crown;
- a documented reason each serious runner-up lost, or the precise unresolved discriminator when the outcome is conditional;
- a stated condition under which the decision should be revisited.
