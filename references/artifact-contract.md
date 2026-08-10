# Artifact contract

## Contents

- File set
- Manifest
- Findings
- Coverage
- Finalization and report

## File set

Keep these files in one scan directory:

```text
scan-manifest.json
findings.json
coverage.json
report.md                 # generated at finalization
artifacts/                # optional PoCs, logs, traces, or screenshots
```

Use UTF-8 JSON with two-space indentation. Use repository-relative forward-slash paths for source locations. Never put secrets, credentials, signed URLs, or local absolute source paths in a distributable report.

The helper at `scripts/security_review.py` creates and validates this format without third-party packages.

## Manifest

Required shape:

```json
{
  "schemaVersion": "1.0",
  "scan": {
    "id": "scan_<stable-id>",
    "mode": "standard",
    "status": "draft",
    "startedAt": "2026-01-01T00:00:00Z",
    "target": {
      "kind": "git_worktree",
      "path": "/local/path",
      "revision": "<git-commit-or-null>"
    },
    "scope": {"includePaths": ["."], "excludePaths": []},
    "coverageRef": "coverage.json",
    "findingsRef": "findings.json"
  }
}
```

Use mode `standard`, `diff`, or `deep`. For diff mode, add `diff` with `kind`, `baseRevision`, `headRevision`, and an optional `workingTree` boolean. Keep status `draft` until all candidates and coverage rows are closed.

Finalization sets `status`, `completedAt`, `sealedAt`, and SHA-256 records for `findings.json`, `coverage.json`, and `report.md`.

## Findings

Required top-level shape:

```json
{
  "schemaVersion": "1.0",
  "scanId": "scan_<same-id>",
  "findings": []
}
```

Each final finding must contain:

- `id`: stable within this scan; omit in a draft to let the helper derive it;
- `ruleId`: lowercase vulnerability-family identifier such as `path-traversal.archive-extraction`;
- `title` and `summary`;
- `severity`: `critical`, `high`, `medium`, or `low`;
- `confidence`: `high`, `medium`, or `low`;
- `taxonomy.cwe`: array such as `["CWE-22"]`, empty when genuinely unknown;
- `locations`: one or more objects with `path`, positive `startLine`, optional `endLine`, and role such as `entrypoint`, `source`, `root_control`, `sink`, or `concrete_implementation`;
- `rootCause`: object with concise `summary`, `source`, `control`, and `sink` facts;
- `validation`: object with `disposition`, `method`, `evidence`, `counterevidence`, and `proofGap`;
- `attackPath`: object with `decision`, `attacker`, `entrypoint`, `dataflow`, `preconditions`, `controls`, `sink`, `impact`, `likelihood`, `severityRationale`, and `counterevidence`;
- `remediation`: practical boundary-closing guidance;
- `remediationTests`: array of focused malicious and legitimate test cases;
- `provenance`: reviewer, tool, supplied report, or advisory source without secrets.

Final findings may use validation disposition only `reportable`. Keep suppressed, not-applicable, and deferred candidates in working notes or a candidate ledger; reflect deferred work in `coverage.json`. Do not silently discard them.

Use `attackPath.decision: "reportable"` for final findings. If the path is ignored or deferred, do not include it as a final finding.

## Coverage

Required shape:

```json
{
  "schemaVersion": "1.0",
  "scanId": "scan_<same-id>",
  "mode": "standard",
  "completeness": "partial",
  "surfaces": [],
  "explicitExclusions": [],
  "deferred": [],
  "openQuestions": []
}
```

Each surface must contain `id`, `label`, and `disposition`. Use disposition `reviewed`, `reported`, `no_finding`, `not_applicable`, or `deferred`. Add `paths`, `notes`, or `evidence` when useful.

Set completeness to `complete` only when every requested surface and source inventory row is closed and no material deferred item or open question remains. Otherwise use `partial`; use `unknown` only when the inventory itself cannot be established.

Each exclusion or deferred entry must state what was omitted and why. Do not use an exclusion to hide a failed validation attempt.

## Finalization and report

Run validation while the manifest is a draft:

```text
python3 <skill-dir>/scripts/security_review.py validate --scan-dir <scan-dir>
```

Finalize only after the JSON represents the completed review:

```text
python3 <skill-dir>/scripts/security_review.py finalize --scan-dir <scan-dir>
```

Finalization:

1. validates the three files and scan-ID consistency;
2. derives missing stable finding IDs and fingerprints from `ruleId`, identity anchor, and primary location;
3. generates `report.md` from the canonical JSON;
4. seals artifact hashes and completion timestamps;
5. validates the sealed bundle again.

Do not edit a sealed bundle silently. Copy it, remove the seal fields, set status back to `draft`, make the correction, and finalize the new version. Never claim a hash verifies bytes that changed after sealing.
