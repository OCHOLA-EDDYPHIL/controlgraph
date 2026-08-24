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


def test_agent_sdk_imports_are_confined_to_the_optional_adk_integration() -> None:
    package_root = Path(__file__).parents[1] / "src" / "controlgraph_canary"
    violations: list[str] = []

    for source_path in package_root.rglob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
            if any(
                module == "google.adk"
                or module.startswith("google.adk.")
                or module == "google.genai"
                or module.startswith("google.genai.")
                for module in modules
            ) and "integrations/adk" not in source_path.as_posix():
                violations.append(str(source_path.relative_to(package_root)))

    assert violations == []
