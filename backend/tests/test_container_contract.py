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


def test_reference_images_have_distinct_fixed_behavior_entrypoints() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM runtime AS reference-stable" in dockerfile
    assert 'CMD ["controlgraph-canary", "serve-reference-stable"]' in dockerfile
    assert "FROM runtime AS reference-candidate" in dockerfile
    assert 'CMD ["controlgraph-canary", "serve-reference-candidate"]' in dockerfile
    assert dockerfile.rstrip().endswith('CMD ["controlgraph-canary", "serve"]')


def test_controller_image_can_dispatch_the_packaged_evidence_writer() -> None:
    backend = Path(__file__).parents[1]
    cli = (backend / "src/controlgraph_canary/cli.py").read_text(encoding="utf-8")

    assert (backend / "src/controlgraph_canary/services/evidence_writer/app.py").is_file()
    assert 'f"controlgraph_canary.services.{settings.role}.app:app"' in cli
    assert (backend / "Dockerfile").read_text(encoding="utf-8").rstrip().endswith(
        'CMD ["controlgraph-canary", "serve"]'
    )
