from pathlib import Path


def test_container_install_is_lockfile_frozen_and_unprivileged() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")

    lock_copy = "COPY pyproject.toml uv.lock README.md ./"
    source_copy = "COPY src ./src"
    assert lock_copy in dockerfile
    assert dockerfile.index(lock_copy) < dockerfile.index(source_copy)
    assert "uv sync --frozen --no-dev --no-install-project" in dockerfile
    assert "uv sync --frozen --no-dev --no-editable" in dockerfile
    assert "pip install --no-cache-dir ." not in dockerfile
    assert "USER 65532:65532" in dockerfile
