#!/usr/bin/env python3
"""Portable source inventory and SECURITY.md policy resolution."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


MAX_POLICY_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 5 * 1024 * 1024
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target", "__pycache__"}
SOURCE_SUFFIXES = {
    ".asm", ".bash", ".bat", ".c", ".cc", ".cfg", ".clj", ".cljs", ".cmake", ".conf",
    ".cpp", ".cs", ".css", ".cxx", ".daml", ".dart", ".dockerfile", ".env", ".ex", ".exs",
    ".fs", ".fsx", ".go", ".graphql", ".h", ".hbs", ".hh", ".hpp", ".html", ".ini", ".java",
    ".js", ".json", ".jsx", ".kt", ".kts", ".lua", ".m", ".md", ".mm", ".php", ".pl",
    ".pm", ".proto", ".ps1", ".py", ".rb", ".rs", ".scala", ".scss", ".sh", ".sol", ".sql",
    ".swift", ".tf", ".tfvars", ".toml", ".ts", ".tsx", ".vue", ".xml", ".yaml", ".yml", ".zig",
}
SOURCE_NAMES = {
    "CMakeLists.txt", "Containerfile", "Dockerfile", "Gemfile", "Justfile", "Makefile", "Podfile",
    "Rakefile", "SECURITY.md", "Vagrantfile", "go.mod", "go.sum", "package-lock.json", "package.json",
    "pnpm-lock.yaml", "pyproject.toml", "requirements.txt", "settings.gradle", "settings.gradle.kts",
    "webpack.config.js", "yarn.lock",
}


class ScopeError(Exception):
    pass


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="\n", dir=path.parent, prefix=f".{path.name}.", delete=False
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


def repo_root(value: str) -> Path:
    root = Path(value).expanduser().resolve()
    if not root.is_dir():
        raise ScopeError(f"repository root is not a directory: {root}")
    return root


def relative_path(root: Path, value: str) -> str:
    raw = value.replace("\\", "/").strip() or "."
    posix = PurePosixPath(raw)
    if posix.is_absolute() or ".." in posix.parts:
        raise ScopeError(f"path must be relative and must not contain '..': {value!r}")
    candidate = (root / Path(*posix.parts)).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ScopeError(f"path escapes repository: {value!r}") from exc
    normalized = candidate.relative_to(root).as_posix()
    return normalized or "."


def contained_regular_file(root: Path, relative: str, max_bytes: int | None = None) -> Path | None:
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    if not resolved.is_file():
        return None
    if max_bytes is not None and resolved.stat().st_size > max_bytes:
        return None
    return resolved


def run_git(root: Path, args: list[str]) -> bytes | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    return completed.stdout


def split_nul(value: bytes) -> list[str]:
    return [item.decode("utf-8", errors="surrogateescape") for item in value.split(b"\0") if item]


def scope_requires_dir(relative_dir: str, scopes: list[str] | None) -> bool:
    if not scopes:
        return False
    return any(
        scope != "."
        and (scope == relative_dir or scope.startswith(relative_dir + "/") or relative_dir.startswith(scope + "/"))
        for scope in scopes
    )


def iter_walk_files(root: Path, scopes: list[str] | None = None) -> Iterable[str]:
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for name in dirs:
            child = current_path / name
            relative_child = child.relative_to(root).as_posix()
            if (name in SKIP_DIRS and not scope_requires_dir(relative_child, scopes)) or child.is_symlink():
                continue
            kept_dirs.append(name)
        dirs[:] = kept_dirs
        for name in files:
            candidate = current_path / name
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError):
                continue
            if resolved.is_file():
                yield candidate.relative_to(root).as_posix()


def all_repo_files(root: Path, scopes: list[str]) -> list[str]:
    output = run_git(root, ["rev-parse", "--is-inside-work-tree"])
    if output and output.strip() == b"true":
        listed = run_git(root, ["ls-files", "--cached", "--others", "--exclude-standard", "-z"])
        if listed is not None:
            return sorted(set(split_nul(listed)))
    return sorted(set(iter_walk_files(root, scopes)))


def is_source_like(path: str) -> bool:
    candidate = PurePosixPath(path)
    name = candidate.name
    suffix = candidate.suffix.lower()
    if name in SOURCE_NAMES or suffix in SOURCE_SUFFIXES:
        return True
    if name.startswith("Dockerfile.") or name.startswith("Containerfile."):
        return True
    return False


def under_scope(path: str, scopes: list[str], excludes: list[str]) -> bool:
    def contains(prefix: str, child: str) -> bool:
        return prefix == "." or child == prefix or child.startswith(prefix.rstrip("/") + "/")

    return any(contains(scope, path) for scope in scopes) and not any(contains(exclude, path) for exclude in excludes)


def diff_files(root: Path, base: str | None, head: str | None, working_tree: bool) -> list[str]:
    if working_tree:
        args = ["diff", "--name-only", "--diff-filter=ACMR", "-z"]
        if base:
            args.append(base)
        tracked = run_git(root, args)
        if tracked is None:
            raise ScopeError("unable to resolve the requested working-tree diff")
        untracked = run_git(root, ["ls-files", "--others", "--exclude-standard", "-z"])
        return sorted(set(split_nul(tracked) + split_nul(untracked or b"")))
    if not base or not head:
        raise ScopeError("revision diff inventory requires both --base and --head")
    listed = run_git(root, ["diff", "--name-only", "--diff-filter=ACMR", "-z", base, head, "--"])
    if listed is None:
        raise ScopeError("unable to resolve the requested revision diff")
    return sorted(set(split_nul(listed)))


def command_inventory(args: argparse.Namespace) -> int:
    root = repo_root(args.repo)
    scopes = [relative_path(root, value) for value in (args.scope or ["."])]
    excludes = [relative_path(root, value) for value in (args.exclude or [])]
    if args.mode == "diff":
        candidates = diff_files(root, args.base, args.head, args.working_tree)
    else:
        candidates = all_repo_files(root, scopes)

    rows: list[dict[str, Any]] = []
    for relative in candidates:
        normalized = relative.replace("\\", "/")
        if not under_scope(normalized, scopes, excludes) or not is_source_like(normalized):
            continue
        resolved = contained_regular_file(root, normalized, MAX_SOURCE_BYTES)
        if resolved is None:
            continue
        rows.append({"path": normalized, "size": resolved.stat().st_size})

    content = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows)
    if args.output == "-":
        sys.stdout.write(content)
    else:
        atomic_write_text(Path(args.output).expanduser().resolve(), content)
        print(json.dumps({"output": str(Path(args.output).expanduser().resolve()), "files": len(rows)}))
    return 0


def inventory_policy_paths(root: Path) -> list[str]:
    policies: list[str] = []
    for relative in iter_walk_files(root):
        if PurePosixPath(relative).name != "SECURITY.md":
            continue
        candidate = root / relative
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
            size = resolved.stat().st_size
        except (OSError, ValueError):
            continue
        if size > MAX_POLICY_BYTES:
            policies.append(relative + " [TOO_LARGE]")
        else:
            policies.append(relative)
    return sorted(policies)


def policy_chain(root: Path, scope: str) -> list[str]:
    normalized = relative_path(root, scope)
    candidate = root if normalized == "." else root / normalized
    directory = candidate if candidate.is_dir() else candidate.parent
    try:
        directory.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise ScopeError("scope escapes repository") from exc
    chain: list[str] = []
    current = root
    root_policy = current / "SECURITY.md"
    if root_policy.exists():
        chain.append("SECURITY.md")
    if directory != root:
        for part in directory.relative_to(root).parts:
            current = current / part
            policy = current / "SECURITY.md"
            if policy.exists():
                chain.append(policy.relative_to(root).as_posix())
    return chain


def command_policy(args: argparse.Namespace) -> int:
    root = repo_root(args.repo)
    if args.list:
        print(json.dumps(inventory_policy_paths(root), indent=2, ensure_ascii=False))
        return 0

    paths = policy_chain(root, args.scope)
    policies: list[dict[str, str]] = []
    for relative in paths:
        resolved = contained_regular_file(root, relative, MAX_POLICY_BYTES)
        if resolved is None:
            raise ScopeError(f"policy is missing, outside the repository, not regular, or over 1 MiB: {relative}")
        try:
            content = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ScopeError(f"cannot read UTF-8 policy {relative}: {exc}") from exc
        policies.append({"path": relative, "content": content})
    print(json.dumps({"scope": relative_path(root, args.scope), "policies": policies}, indent=2, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory = subparsers.add_parser("inventory", help="write a deterministic source-like file inventory")
    inventory.add_argument("--repo", required=True)
    inventory.add_argument("--output", required=True, help="JSONL path or - for stdout")
    inventory.add_argument("--mode", choices=("standard", "deep", "diff"), default="standard")
    inventory.add_argument("--scope", action="append", help="relative included path; repeatable")
    inventory.add_argument("--exclude", action="append", help="relative excluded path; repeatable")
    inventory.add_argument("--base", help="diff base revision")
    inventory.add_argument("--head", help="diff head revision")
    inventory.add_argument("--working-tree", action="store_true")
    inventory.set_defaults(func=command_inventory)

    policy = subparsers.add_parser("policy", help="list policies or resolve the root-to-leaf chain")
    policy.add_argument("--repo", required=True)
    policy.add_argument("--scope", default=".")
    policy.add_argument("--list", action="store_true", help="list all repository SECURITY.md paths")
    policy.set_defaults(func=command_policy)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("ERROR: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
