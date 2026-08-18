import ast
from pathlib import Path


def test_authority_package_has_only_standard_library_imports() -> None:
    authority_root = (
        Path(__file__).parents[1] / "src" / "controlgraph_canary" / "authority"
    )
    violations: list[str] = []

    for source_path in authority_root.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                violations.extend(
                    f"{source_path.name}: {alias.name}"
                    for alias in node.names
                    if alias.name != "dataclasses"
                )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module not in {"dataclasses", "controlgraph_canary.authority.epoch"}:
                    violations.append(f"{source_path.name}: {module}")

    assert violations == []
