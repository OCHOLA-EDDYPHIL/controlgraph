#!/usr/bin/env python3
"""Fail CI on source-boundary violations, linked files, or committed secrets."""

from __future__ import annotations

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    ".venv",
    "dist",
    "node_modules",
    "__pycache__",
}
TEXT_SUFFIXES = {
    "",
    ".css",
    ".html",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yml",
    ".yaml",
}
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"gh(?:p|o|u|s|r)_[A-Za-z0-9_]{30,}"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "service-account key": re.compile(r'"type"\s*:\s*"service_account"'),
}
FORBIDDEN_REFERENCES = {
    "copied Devpost state": re.compile(r"\.devpost-hackathon-state\.json"),
}


def sibling_imports(path: Path, text: str) -> list[str]:
    """Return direct runtime imports from the sibling RECONCILE package."""

    if path.suffix != ".py":
        return []
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as error:
        return [f"cannot inspect Python source {path.relative_to(ROOT)}: {error}"]

    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported = [node.module or ""]
        else:
            continue
        if any(name == "reconcile" or name.startswith("reconcile.") for name in imported):
            violations.append(
                f"runtime sibling import found in {path.relative_to(ROOT)}"
            )
    return violations


def candidate_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and not any(part in SKIP_PARTS for part in path.relative_to(ROOT).parts)
        and path.suffix.lower() in TEXT_SUFFIXES
    )


def main() -> int:
    failures: list[str] = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            failures.append(f"symlink is forbidden: {path.relative_to(ROOT)}")

    for path in candidate_files():
        if path == Path(__file__).resolve():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        relative = path.relative_to(ROOT)
        for name, pattern in {**SECRET_PATTERNS, **FORBIDDEN_REFERENCES}.items():
            if pattern.search(text):
                failures.append(f"{name} found in {relative}")
        failures.extend(sibling_imports(path, text))

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1
    print(f"source-boundary check passed ({len(candidate_files())} text files inspected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
