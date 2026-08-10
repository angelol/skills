#!/usr/bin/env python3
"""Create, validate, seal, and render portable security-review artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA_VERSION = "1.0"
MODES = {"standard", "diff", "deep"}
SEVERITIES = {"critical", "high", "medium", "low"}
CONFIDENCES = {"high", "medium", "low"}
COMPLETENESS = {"complete", "partial", "unknown"}
SURFACE_DISPOSITIONS = {
    "reviewed",
    "reported",
    "no_finding",
    "not_applicable",
    "deferred",
}
LOCATION_ROLES = {
    "entrypoint",
    "source",
    "root_control",
    "sink",
    "concrete_implementation",
    "affected",
    "supporting",
}
RULE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
CWE_RE = re.compile(r"^CWE-[1-9][0-9]*$")


class ContractError(Exception):
    """Raised for an invalid artifact bundle."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContractError(f"missing required file: {path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"top-level JSON value must be an object: {path}")
    return value


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_value(target: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(target), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            timeout=10,
        )
    except (FileNotFoundError, subprocess.SubprocessError, UnicodeError):
        return None
    value = completed.stdout.strip()
    return value or None


def normalize_scope_path(value: str) -> str:
    normalized = value.replace("\\", "/").strip()
    if normalized == ".":
        return normalized
    normalized = normalized.rstrip("/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise ContractError(f"scope path must be repository-relative without '..': {value!r}")
    return normalized


def valid_source_path(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip() or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and value not in {".", ""}


def nonempty(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value)
    return value is not None


def require_string(obj: dict[str, Any], key: str, where: str, errors: list[str]) -> None:
    if not isinstance(obj.get(key), str) or not obj[key].strip():
        errors.append(f"{where}.{key} must be a non-empty string")


def validate_location(location: Any, where: str, errors: list[str]) -> None:
    if not isinstance(location, dict):
        errors.append(f"{where} must be an object")
        return
    if not valid_source_path(location.get("path")):
        errors.append(f"{where}.path must be a repository-relative forward-slash path")
    start = location.get("startLine")
    end = location.get("endLine", start)
    if not isinstance(start, int) or isinstance(start, bool) or start < 1:
        errors.append(f"{where}.startLine must be a positive integer")
    if not isinstance(end, int) or isinstance(end, bool) or end < 1:
        errors.append(f"{where}.endLine must be a positive integer")
    elif isinstance(start, int) and end < start:
        errors.append(f"{where}.endLine must be greater than or equal to startLine")
    role = location.get("role")
    if role is not None and role not in LOCATION_ROLES:
        errors.append(f"{where}.role must be one of {sorted(LOCATION_ROLES)}")


def validate_finding(finding: Any, index: int, errors: list[str], sealed: bool) -> None:
    where = f"findings.findings[{index}]"
    if not isinstance(finding, dict):
        errors.append(f"{where} must be an object")
        return

    if sealed:
        require_string(finding, "id", where, errors)
        require_string(finding, "fingerprint", where, errors)
    require_string(finding, "ruleId", where, errors)
    require_string(finding, "title", where, errors)
    require_string(finding, "summary", where, errors)
    require_string(finding, "remediation", where, errors)

    if isinstance(finding.get("ruleId"), str) and not RULE_RE.fullmatch(finding["ruleId"]):
        errors.append(f"{where}.ruleId must be a lowercase vulnerability-family identifier")
    if finding.get("severity") not in SEVERITIES:
        errors.append(f"{where}.severity must be one of {sorted(SEVERITIES)}")
    if finding.get("confidence") not in CONFIDENCES:
        errors.append(f"{where}.confidence must be one of {sorted(CONFIDENCES)}")

    taxonomy = finding.get("taxonomy")
    if not isinstance(taxonomy, dict) or not isinstance(taxonomy.get("cwe"), list):
        errors.append(f"{where}.taxonomy.cwe must be an array")
    else:
        for cwe_index, cwe in enumerate(taxonomy["cwe"]):
            if not isinstance(cwe, str) or not CWE_RE.fullmatch(cwe):
                errors.append(f"{where}.taxonomy.cwe[{cwe_index}] must match CWE-<positive integer>")

    locations = finding.get("locations")
    if not isinstance(locations, list) or not locations:
        errors.append(f"{where}.locations must contain at least one location")
    else:
        for location_index, location in enumerate(locations):
            validate_location(location, f"{where}.locations[{location_index}]", errors)

    root = finding.get("rootCause")
    if not isinstance(root, dict):
        errors.append(f"{where}.rootCause must be an object")
    else:
        for key in ("summary", "source", "control", "sink"):
            require_string(root, key, f"{where}.rootCause", errors)

    validation = finding.get("validation")
    if not isinstance(validation, dict):
        errors.append(f"{where}.validation must be an object")
    else:
        if validation.get("disposition") != "reportable":
            errors.append(f"{where}.validation.disposition must be 'reportable' for final findings")
        for key in ("method", "evidence", "counterevidence", "proofGap"):
            if key not in validation:
                errors.append(f"{where}.validation.{key} is required (use an empty string when none)")
            elif key in {"method", "evidence"} and not nonempty(validation[key]):
                errors.append(f"{where}.validation.{key} must not be empty")

    attack = finding.get("attackPath")
    if not isinstance(attack, dict):
        errors.append(f"{where}.attackPath must be an object")
    else:
        if attack.get("decision") != "reportable":
            errors.append(f"{where}.attackPath.decision must be 'reportable' for final findings")
        for key in (
            "attacker",
            "entrypoint",
            "dataflow",
            "preconditions",
            "controls",
            "sink",
            "impact",
            "likelihood",
            "severityRationale",
            "counterevidence",
        ):
            if key not in attack:
                errors.append(f"{where}.attackPath.{key} is required (use an empty string when none)")
        if attack.get("likelihood") not in {"high", "medium", "low", "unknown"}:
            errors.append(f"{where}.attackPath.likelihood must be high, medium, low, or unknown")

    tests = finding.get("remediationTests")
    if not isinstance(tests, list):
        errors.append(f"{where}.remediationTests must be an array")
    provenance = finding.get("provenance")
    if not isinstance(provenance, (dict, str)) or (isinstance(provenance, str) and not provenance.strip()):
        errors.append(f"{where}.provenance must be an object or non-empty string")


def validate_bundle(scan_dir: Path, require_sealed: bool | None = None) -> list[str]:
    errors: list[str] = []
    try:
        manifest = read_json(scan_dir / "scan-manifest.json")
        findings = read_json(scan_dir / "findings.json")
        coverage = read_json(scan_dir / "coverage.json")
    except ContractError as exc:
        return [str(exc)]

    scan = manifest.get("scan")
    if manifest.get("schemaVersion") != SCHEMA_VERSION:
        errors.append(f"scan-manifest.schemaVersion must be {SCHEMA_VERSION!r}")
    if not isinstance(scan, dict):
        return errors + ["scan-manifest.scan must be an object"]

    require_string(scan, "id", "scan-manifest.scan", errors)
    require_string(scan, "startedAt", "scan-manifest.scan", errors)
    if scan.get("mode") not in MODES:
        errors.append(f"scan-manifest.scan.mode must be one of {sorted(MODES)}")
    if scan.get("status") not in {"draft", "completed"}:
        errors.append("scan-manifest.scan.status must be 'draft' or 'completed'")
    if scan.get("coverageRef") != "coverage.json" or scan.get("findingsRef") != "findings.json":
        errors.append("scan-manifest refs must be coverage.json and findings.json")

    target = scan.get("target")
    if not isinstance(target, dict):
        errors.append("scan-manifest.scan.target must be an object")
    else:
        if target.get("kind") not in {"git_worktree", "directory"}:
            errors.append("scan-manifest.scan.target.kind must be git_worktree or directory")
        require_string(target, "path", "scan-manifest.scan.target", errors)

    scope = scan.get("scope")
    if not isinstance(scope, dict):
        errors.append("scan-manifest.scan.scope must be an object")
    else:
        for key in ("includePaths", "excludePaths"):
            values = scope.get(key)
            if not isinstance(values, list):
                errors.append(f"scan-manifest.scan.scope.{key} must be an array")
                continue
            for index, value in enumerate(values):
                try:
                    normalize_scope_path(value)
                except (ContractError, AttributeError):
                    errors.append(f"scan-manifest.scan.scope.{key}[{index}] is not a safe relative path")

    sealed = scan.get("status") == "completed" or bool(scan.get("sealedAt"))
    if require_sealed is True and not sealed:
        errors.append("bundle is not sealed")
    if require_sealed is False and sealed:
        errors.append("bundle is already sealed")
    if sealed:
        require_string(scan, "completedAt", "scan-manifest.scan", errors)
        require_string(scan, "sealedAt", "scan-manifest.scan", errors)
        artifacts = scan.get("artifacts")
        if not isinstance(artifacts, list) or len(artifacts) != 3:
            errors.append("sealed manifest must contain three artifact digest records")
        else:
            expected_paths = {"findings.json", "coverage.json", "report.md"}
            actual_paths = {item.get("path") for item in artifacts if isinstance(item, dict)}
            if actual_paths != expected_paths:
                errors.append(f"sealed artifacts must be exactly {sorted(expected_paths)}")
            for index, item in enumerate(artifacts):
                if not isinstance(item, dict):
                    errors.append(f"scan-manifest.scan.artifacts[{index}] must be an object")
                    continue
                path_value = item.get("path")
                digest_value = item.get("sha256")
                if path_value in expected_paths:
                    artifact_path = scan_dir / path_value
                    if not artifact_path.is_file():
                        errors.append(f"sealed artifact is missing: {path_value}")
                    elif digest_value != sha256_file(artifact_path):
                        errors.append(f"sealed artifact digest mismatch: {path_value}")

    scan_id = scan.get("id")
    if findings.get("schemaVersion") != SCHEMA_VERSION:
        errors.append(f"findings.schemaVersion must be {SCHEMA_VERSION!r}")
    if findings.get("scanId") != scan_id:
        errors.append("findings.scanId must match scan-manifest.scan.id")
    finding_list = findings.get("findings")
    if not isinstance(finding_list, list):
        errors.append("findings.findings must be an array")
    else:
        ids: set[str] = set()
        fingerprints: set[str] = set()
        for index, finding in enumerate(finding_list):
            validate_finding(finding, index, errors, sealed)
            if isinstance(finding, dict):
                finding_id = finding.get("id")
                fingerprint = finding.get("fingerprint")
                if finding_id and finding_id in ids:
                    errors.append(f"duplicate finding id: {finding_id}")
                if fingerprint and fingerprint in fingerprints:
                    errors.append(f"duplicate finding fingerprint: {fingerprint}")
                if finding_id:
                    ids.add(finding_id)
                if fingerprint:
                    fingerprints.add(fingerprint)

    if coverage.get("schemaVersion") != SCHEMA_VERSION:
        errors.append(f"coverage.schemaVersion must be {SCHEMA_VERSION!r}")
    if coverage.get("scanId") != scan_id:
        errors.append("coverage.scanId must match scan-manifest.scan.id")
    if coverage.get("mode") != scan.get("mode"):
        errors.append("coverage.mode must match scan-manifest.scan.mode")
    if coverage.get("completeness") not in COMPLETENESS:
        errors.append(f"coverage.completeness must be one of {sorted(COMPLETENESS)}")

    surfaces = coverage.get("surfaces")
    has_deferred_surface = False
    if not isinstance(surfaces, list):
        errors.append("coverage.surfaces must be an array")
    else:
        surface_ids: set[str] = set()
        for index, surface in enumerate(surfaces):
            where = f"coverage.surfaces[{index}]"
            if not isinstance(surface, dict):
                errors.append(f"{where} must be an object")
                continue
            require_string(surface, "id", where, errors)
            require_string(surface, "label", where, errors)
            disposition = surface.get("disposition")
            if disposition not in SURFACE_DISPOSITIONS:
                errors.append(f"{where}.disposition must be one of {sorted(SURFACE_DISPOSITIONS)}")
            has_deferred_surface = has_deferred_surface or disposition == "deferred"
            surface_id = surface.get("id")
            if surface_id in surface_ids:
                errors.append(f"duplicate coverage surface id: {surface_id}")
            if isinstance(surface_id, str):
                surface_ids.add(surface_id)

    for key in ("explicitExclusions", "deferred", "openQuestions"):
        if not isinstance(coverage.get(key), list):
            errors.append(f"coverage.{key} must be an array")
    if coverage.get("completeness") == "complete":
        if not surfaces:
            errors.append("coverage cannot be complete without at least one reviewed surface")
        if coverage.get("deferred") or coverage.get("openQuestions") or has_deferred_surface:
            errors.append("coverage cannot be complete while deferred work or open questions remain")

    return errors


def stable_finding_identity(finding: dict[str, Any]) -> tuple[str, str]:
    locations = finding.get("locations") or []
    primary = locations[0] if locations else {}
    identity = finding.get("identity")
    anchor = identity.get("anchor") if isinstance(identity, dict) else None
    if not anchor:
        anchor = f"{primary.get('path', '')}:{primary.get('startLine', '')}"
    instance = identity.get("instance") if isinstance(identity, dict) else ""
    semantic = "\0".join(
        [
            str(finding.get("ruleId", "")),
            str(anchor),
            str(instance or ""),
            str(primary.get("path", "")),
            str(primary.get("startLine", "")),
        ]
    )
    digest = hashlib.sha256(semantic.encode("utf-8")).hexdigest()
    return f"sec_{digest[:24]}", f"security-review/v1:sha256:{digest}"


def derive_finding_identities(findings_doc: dict[str, Any]) -> None:
    for finding in findings_doc.get("findings", []):
        if not isinstance(finding, dict):
            continue
        finding_id, fingerprint = stable_finding_identity(finding)
        finding.setdefault("id", finding_id)
        finding.setdefault("fingerprint", fingerprint)


def markdown_text(value: Any) -> str:
    if isinstance(value, list):
        return "; ".join(str(item) for item in value) or "None recorded."
    if isinstance(value, dict):
        return "; ".join(f"{key}: {item}" for key, item in value.items()) or "None recorded."
    text = str(value or "").strip()
    return text or "None recorded."


def render_report(manifest: dict[str, Any], findings: dict[str, Any], coverage: dict[str, Any]) -> str:
    scan = manifest["scan"]
    target = scan["target"]
    finding_list = findings.get("findings", [])
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    finding_list = sorted(
        finding_list,
        key=lambda item: (severity_order.get(item.get("severity"), 9), item.get("title", "")),
    )
    lines = [
        "# Security Review",
        "",
        "## Summary",
        "",
        f"- Mode: `{scan['mode']}`",
        f"- Target: `{Path(target['path']).name}` ({target['kind']})",
        f"- Revision: `{target.get('revision') or 'not available'}`",
        f"- Findings: {len(finding_list)}",
        f"- Coverage: `{coverage['completeness']}`",
        "",
    ]

    if finding_list:
        counts = {severity: 0 for severity in ("critical", "high", "medium", "low")}
        for finding in finding_list:
            counts[finding["severity"]] += 1
        lines.extend(
            [
                "Severity totals: " + ", ".join(f"{name} {count}" for name, count in counts.items()),
                "",
                "## Findings",
                "",
            ]
        )
        for number, finding in enumerate(finding_list, 1):
            cwes = finding.get("taxonomy", {}).get("cwe", [])
            lines.extend(
                [
                    f"### {number}. {finding['title']}",
                    "",
                    f"- ID: `{finding['id']}`",
                    f"- Rule: `{finding['ruleId']}`",
                    f"- Severity: `{finding['severity']}`",
                    f"- Confidence: `{finding['confidence']}`",
                    f"- CWE: {', '.join(cwes) if cwes else 'Not established'}",
                    "",
                    finding["summary"],
                    "",
                    "Locations:",
                    "",
                ]
            )
            for location in finding["locations"]:
                end = location.get("endLine", location["startLine"])
                span = str(location["startLine"]) if end == location["startLine"] else f"{location['startLine']}-{end}"
                role = location.get("role", "affected")
                lines.append(f"- `{location['path']}:{span}` ({role})")
            root = finding["rootCause"]
            validation = finding["validation"]
            attack = finding["attackPath"]
            lines.extend(
                [
                    "",
                    f"**Root cause:** {root['summary']}",
                    "",
                    f"**Source/control/sink:** {root['source']} / {root['control']} / {root['sink']}",
                    "",
                    f"**Validation:** {validation['method']}. Evidence: {markdown_text(validation['evidence'])}",
                    "",
                    f"**Counterevidence and proof gap:** {markdown_text(validation['counterevidence'])} Proof gap: {markdown_text(validation['proofGap'])}",
                    "",
                    f"**Attack path:** {attack['attacker']} reaches {attack['entrypoint']}; {attack['dataflow']} The sensitive operation is {attack['sink']}.",
                    "",
                    f"**Preconditions and controls:** {markdown_text(attack['preconditions'])} Existing controls: {markdown_text(attack['controls'])}",
                    "",
                    f"**Impact and likelihood:** {attack['impact']} Likelihood: {attack['likelihood']}. {attack['severityRationale']}",
                    "",
                    f"**Remediation:** {finding['remediation']}",
                    "",
                    "Regression tests:",
                    "",
                ]
            )
            tests = finding.get("remediationTests", [])
            if tests:
                lines.extend(f"- {markdown_text(test)}" for test in tests)
            else:
                lines.append("- No test recommendation recorded.")
            lines.append("")
    else:
        lines.extend(
            [
                "## Findings",
                "",
                "No reportable findings survived validation. This is not a claim that the target is secure.",
                "",
            ]
        )

    lines.extend(["## Coverage", "", "| Surface | Disposition | Notes |", "| --- | --- | --- |"])
    for surface in coverage.get("surfaces", []):
        notes = markdown_text(surface.get("notes", surface.get("evidence", ""))).replace("|", "\\|")
        label = surface["label"].replace("|", "\\|")
        lines.append(f"| {label} | `{surface['disposition']}` | {notes} |")
    if not coverage.get("surfaces"):
        lines.append("| No surfaces recorded | `unknown` | Coverage inventory is empty. |")
    lines.extend(["", "### Exclusions", ""])
    exclusions = coverage.get("explicitExclusions", [])
    lines.extend(f"- {markdown_text(item)}" for item in exclusions) if exclusions else lines.append("- None recorded.")
    lines.extend(["", "### Deferred work", ""])
    deferred = coverage.get("deferred", [])
    lines.extend(f"- {markdown_text(item)}" for item in deferred) if deferred else lines.append("- None recorded.")
    lines.extend(["", "### Open questions", ""])
    questions = coverage.get("openQuestions", [])
    lines.extend(f"- {markdown_text(item)}" for item in questions) if questions else lines.append("- None recorded.")
    lines.extend(["", "---", "", "Generated from the canonical JSON artifacts in this review bundle.", ""])
    return "\n".join(lines)


def command_init(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        raise ContractError(f"target is not a directory: {target}")
    output = Path(args.output).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    canonical = [output / name for name in ("scan-manifest.json", "findings.json", "coverage.json")]
    if any(path.exists() for path in canonical):
        raise ContractError(f"refusing to overwrite an existing review bundle in {output}")

    scan_id = args.scan_id or f"scan_{uuid.uuid4().hex[:20]}"
    revision = git_value(target, "rev-parse", "HEAD")
    git_root = git_value(target, "rev-parse", "--show-toplevel")
    include_paths = [normalize_scope_path(value) for value in (args.include or ["."])]
    exclude_paths = [normalize_scope_path(value) for value in (args.exclude or [])]
    target_doc: dict[str, Any] = {
        "kind": "git_worktree" if git_root else "directory",
        "path": str(target),
        "revision": revision,
    }
    if git_root:
        remote = git_value(target, "remote", "get-url", "origin")
        if remote:
            target_doc["remote"] = remote

    scan: dict[str, Any] = {
        "id": scan_id,
        "mode": args.mode,
        "status": "draft",
        "startedAt": utc_now(),
        "target": target_doc,
        "scope": {"includePaths": include_paths, "excludePaths": exclude_paths},
        "coverageRef": "coverage.json",
        "findingsRef": "findings.json",
    }
    if args.mode == "diff":
        scan["diff"] = {
            "kind": "working_tree" if args.working_tree else "range",
            "baseRevision": args.base,
            "headRevision": args.head or revision,
            "workingTree": bool(args.working_tree),
        }

    manifest = {"schemaVersion": SCHEMA_VERSION, "scan": scan}
    findings = {"schemaVersion": SCHEMA_VERSION, "scanId": scan_id, "findings": []}
    coverage = {
        "schemaVersion": SCHEMA_VERSION,
        "scanId": scan_id,
        "mode": args.mode,
        "completeness": "unknown",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
        "openQuestions": [],
    }
    atomic_write_json(output / "scan-manifest.json", manifest)
    atomic_write_json(output / "findings.json", findings)
    atomic_write_json(output / "coverage.json", coverage)
    (output / "artifacts").mkdir(exist_ok=True)
    print(json.dumps({"scanId": scan_id, "scanDir": str(output)}, ensure_ascii=False))
    return 0


def command_validate(args: argparse.Namespace) -> int:
    scan_dir = Path(args.scan_dir).expanduser().resolve()
    errors = validate_bundle(scan_dir, require_sealed=True if args.sealed else None)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    state = "sealed" if read_json(scan_dir / "scan-manifest.json")["scan"]["status"] == "completed" else "draft"
    print(f"Valid {state} security-review bundle: {scan_dir}")
    return 0


def command_finalize(args: argparse.Namespace) -> int:
    scan_dir = Path(args.scan_dir).expanduser().resolve()
    manifest_path = scan_dir / "scan-manifest.json"
    findings_path = scan_dir / "findings.json"
    coverage_path = scan_dir / "coverage.json"
    report_path = scan_dir / "report.md"

    manifest = read_json(manifest_path)
    findings = read_json(findings_path)
    coverage = read_json(coverage_path)
    scan = manifest.get("scan", {})
    if scan.get("status") == "completed" or scan.get("sealedAt"):
        raise ContractError("refusing to modify an already sealed bundle")

    derive_finding_identities(findings)
    atomic_write_json(findings_path, findings)
    errors = validate_bundle(scan_dir, require_sealed=False)
    if errors:
        raise ContractError("bundle validation failed:\n- " + "\n- ".join(errors))

    report = render_report(manifest, findings, coverage)
    atomic_write_text(report_path, report)
    completed_at = utc_now()
    scan["status"] = "completed"
    scan["completedAt"] = completed_at
    scan["sealedAt"] = completed_at
    scan["artifacts"] = [
        {"path": "findings.json", "sha256": sha256_file(findings_path), "mediaType": "application/json"},
        {"path": "coverage.json", "sha256": sha256_file(coverage_path), "mediaType": "application/json"},
        {"path": "report.md", "sha256": sha256_file(report_path), "mediaType": "text/markdown"},
    ]
    atomic_write_json(manifest_path, manifest)

    errors = validate_bundle(scan_dir, require_sealed=True)
    if errors:
        raise ContractError("sealed bundle validation failed:\n- " + "\n- ".join(errors))
    print(json.dumps({"scanId": scan["id"], "report": str(report_path), "findings": len(findings["findings"])}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="create a draft review bundle")
    init_parser.add_argument("--target", required=True, help="repository or source directory")
    init_parser.add_argument("--output", required=True, help="new or empty scan directory")
    init_parser.add_argument("--mode", required=True, choices=sorted(MODES))
    init_parser.add_argument("--scan-id", help="optional caller-supplied scan ID")
    init_parser.add_argument("--include", action="append", help="relative included path; repeatable")
    init_parser.add_argument("--exclude", action="append", help="relative excluded path; repeatable")
    init_parser.add_argument("--base", help="diff base revision")
    init_parser.add_argument("--head", help="diff head revision")
    init_parser.add_argument("--working-tree", action="store_true", help="describe a working-tree diff")
    init_parser.set_defaults(func=command_init)

    validate_parser = subparsers.add_parser("validate", help="validate a draft or sealed bundle")
    validate_parser.add_argument("--scan-dir", required=True)
    validate_parser.add_argument("--sealed", action="store_true", help="require valid artifact seals")
    validate_parser.set_defaults(func=command_validate)

    finalize_parser = subparsers.add_parser("finalize", help="derive IDs, render report, and seal bundle")
    finalize_parser.add_argument("--scan-dir", required=True)
    finalize_parser.set_defaults(func=command_finalize)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("ERROR: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
