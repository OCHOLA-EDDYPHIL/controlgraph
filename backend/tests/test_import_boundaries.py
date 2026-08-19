import ast
import sys
from pathlib import Path


def test_authority_package_has_only_standard_library_imports() -> None:
    authority_root = (
        Path(__file__).parents[1] / "src" / "controlgraph_canary" / "authority"
    )
    violations: list[str] = []

    for source_path in authority_root.rglob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                violations.extend(
                    f"{source_path.name}: {alias.name}"
                    for alias in node.names
                    if alias.name.partition(".")[0] not in sys.stdlib_module_names
                )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                root_module = module.partition(".")[0]
                if (
                    root_module not in sys.stdlib_module_names
                    and not module.startswith("controlgraph_canary.authority")
                ):
                    violations.append(f"{source_path.name}: {module}")

    assert violations == []
