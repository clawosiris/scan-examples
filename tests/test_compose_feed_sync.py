from pathlib import Path


COMPOSE = Path("docker-compose.yml").read_text(encoding="utf-8")
CI_COMPOSE = Path("docker-compose.ci.yml").read_text(encoding="utf-8")
WORKFLOW = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")
README = Path("README.md").read_text(encoding="utf-8")


def test_compose_uses_greenbone_feed_sync_instead_of_feed_data_containers():
    assert "greenbone-feed-sync:" in COMPOSE
    assert "registry.community.greenbone.net/community/greenbone-feed-sync" in COMPOSE
    assert "greenbone-feed-sync --type nasl" in COMPOSE
    assert "greenbone-feed-sync --type notus" in COMPOSE
    assert "greenbone-feed-sync --type gvmd-data" in COMPOSE

    assert "community/vulnerability-tests" not in COMPOSE
    assert "community/notus-data" not in COMPOSE
    assert "community/data-objects" not in COMPOSE


def test_compose_mounts_feed_sync_outputs_to_persistent_runtime_volumes():
    assert "vt_data_vol:/var/lib/openvas/plugins" in COMPOSE
    assert "notus_data_vol:/var/lib/notus" in COMPOSE
    assert "data_objects_vol:/var/lib/gvm/data-objects/gvmd" in COMPOSE
    assert "data_objects_vol:/feed/data-objects:ro" in COMPOSE
    assert "vt_data_vol:/feed/vulnerability-tests:ro" in COMPOSE
    assert "notus_data_vol:/var/lib/notus:ro" in COMPOSE

    assert (
        "greenbone-feed-sync:\n        condition: service_completed_successfully"
        in COMPOSE
    )


def test_ci_runs_feed_sync_before_scanner_stack_and_keeps_feed_volumes():
    assert (
        "docker compose -f docker-compose.yml -f docker-compose.ci.yml up greenbone-feed-sync"
        in WORKFLOW
    )
    assert (
        "docker compose -f docker-compose.yml -f docker-compose.ci.yml up -d"
        in WORKFLOW
    )
    assert "gpg-data" in WORKFLOW
    assert "redis-server" in WORKFLOW
    assert "configure-openvas" in WORKFLOW
    assert "openvasd" in WORKFLOW
    assert "target" in WORKFLOW
    assert "services:\n  openvasd:\n    ports: !override []" in CI_COMPOSE
    assert "scan-examples_vt_data_vol" not in WORKFLOW
    assert "scan-examples_notus_data_vol" not in WORKFLOW
    assert "scan-examples_data_objects_vol" not in WORKFLOW


def test_ci_uses_released_mock_scanner_and_gates_real_scan():
    assert (
        "OPENVAS_MOCK_SCANNER_IMAGE: ghcr.io/clawosiris/openvas-mock-scanner:0.2.1"
        in WORKFLOW
    )
    assert "openvas-mock-scanner:latest" not in WORKFLOW
    assert "github.base_ref == 'main'" in WORKFLOW
    assert "startsWith(github.ref, 'refs/tags/v')" in WORKFLOW
    assert "github.event_name == 'workflow_dispatch'" in WORKFLOW


def test_readme_documents_feed_sync_flow():
    assert "docker compose up greenbone-feed-sync" in README
    assert "greenbone-feed-sync --type gvmd-data" in README
    normalized_readme = " ".join(README.split())
    assert "subsequent synchronizations only fetch deltas" in normalized_readme


def test_readme_documents_fast_mock_and_real_scan_split():
    normalized_readme = " ".join(README.split())
    assert "ghcr.io/clawosiris/openvas-mock-scanner:0.2.1" in README
    assert "floating `:latest` tag" in normalized_readme
    assert "pull requests targeting `main`" in normalized_readme
    assert "release tag pushes" in normalized_readme
