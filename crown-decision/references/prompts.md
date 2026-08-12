# Crowning Prompt Library

Use these as scaffolds. Replace bracketed fields and remove irrelevant sections. Keep option definitions identical across critic and jury prompts.

## Ruling card

```text
Decision: [one sentence]

Binding constraints:
- [prior ruling]
- [platform/deployment constraint]

In scope: [scope]
Out of scope: [non-goals]

Evidence baseline:
- Revision/document version: [value]
- Dirty or mutable state: [value]
- Relevant configuration/platform versions: [value]
- Time-sensitive date: [value]

Threat/trust boundary:
- User-declared trusted actors/components: [list]
- User-declared adversarial or failure-prone actors/components: [list]
- Candidate-introduced trust still to evaluate: [unknown]

Decision axes and dependencies:
- [axis]: [independent | depends on ...]

Evaluation order:
1. [hard correctness invariant]
2. [security/liveness]
3. [compatibility/recovery]
4. [scope/complexity]
5. [performance/product semantics]

Evidence:
- [source paths, tests, specifications, measured facts]

Unknowns that could reverse the ruling:
- [unknown]
```

## Advocate prompt

```text
Act as the independent [option or lens] advocate for the attached ruling card. If assigned an option, construct its strongest viable form before comparing it. Work read-only, do not seek consensus, and do not spawn subagents.

Propose the strongest concrete design from your lens. You may reject the listed options or introduce one materially different candidate. Inspect primary evidence.

Return:
1. exact design and lifecycle;
2. invariants it guarantees and does not guarantee;
3. failure, retry, recovery, and migration behavior;
4. trust and authorization assumptions;
5. strongest attack or counterexample against it;
6. comparison and total ranking of alternatives;
7. disqualifying evidence or experiment;
8. required tests and adoption or rollout gates.
```

## Critic prompt

```text
Act as the [comparison duty] critic. Work read-only and do not spawn subagents.

Ruling card:
[card]

Exact finalists:
A. [complete definition]
B. [complete definition]
C. [complete definition]

Verified evidence and corrections:
- [facts]

Compare the exact finalists rather than inventing hybrids unless a hybrid removes a fatal flaw with minimal added machinery.

Return:
1. total ranking;
2. strongest counterexample against each finalist;
3. invariant or assumption each relies on;
4. operational and upgrade consequences;
5. kill criteria;
6. smallest decisive experiment;
7. crown recommendation.
```

## Premise-correction message

```text
Premise status: [disproven | unverified | inapplicable to pinned environment]
Affected premise: [old premise]

Verified evidence: [primary evidence].
Required consequence: identify every proposal, elimination, comparison, or verdict that depends on this premise. Return to the earliest contaminated stage. Discard disproven dependencies; make unverified dependencies conditional or propose a decisive experiment. Reopen candidate generation when this correction changes the viable option space.
```

## Jury prompt

```text
Serve as the independent [delivery | security/reliability | dissent | domain] juror. Work read-only and do not spawn subagents.

Use the ruling card, exact finalist definitions, verified evidence, and corrections below. Inspect the primary evidence behind any premise decisive to your verdict. Do not infer consensus from candidate ordering. Select one crown, declare a conditional tie, or return no crown if every finalist violates a hard invariant.

Return:
1. crown and runner-up;
2. decisive reason;
3. trust boundary and assumptions;
4. non-negotiable safeguards;
5. objective adoption gates, including merge, rollout, or experiment gates when applicable;
6. kill criterion or condition that promotes the runner-up;
7. any intentionally deferred hardening.

Only for dissent duty, first construct the strongest possible case against the apparent favorite. If it survives, say why.
```

## Final ruling template

```markdown
## Crown

[Exact design in one paragraph or compact diagram.]

Why it wins: [decisive reasoning].

## Trust boundary

- Trusted: ...
- Adversarial/failure-prone: ...

## Non-negotiables

- ...

## Adoption gates

- ...

## Evidence baseline

- Revision/version/configuration: ...
- Verified facts versus decision judgments: ...

## Runners-up

- [Option]: lost because ...; promote it if ...

## Revisit when

- ...

## Tournament integrity

- Tier and completed roles: ...
- Material unresolved dissent: ...
```
