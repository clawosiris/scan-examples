from pathlib import Path


COMPOSE = Path("docker-compose.yml").read_text(encoding="utf-8")
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

    assert "greenbone-feed-sync:\n        condition: service_completed_successfully" in COMPOSE


def test_ci_runs_feed_sync_before_scanner_stack_and_keeps_feed_volumes():
    assert "docker compose up greenbone-feed-sync" in WORKFLOW
    assert "docker compose up -d" in WORKFLOW
    assert "gpg-data" in WORKFLOW
    assert "redis-server" in WORKFLOW
    assert "configure-openvas" in WORKFLOW
    assert "openvasd" in WORKFLOW
    assert "target" in WORKFLOW
    assert "scan-examples_vt_data_vol" not in WORKFLOW
    assert "scan-examples_notus_data_vol" not in WORKFLOW
    assert "scan-examples_data_objects_vol" not in WORKFLOW


def test_readme_documents_feed_sync_flow():
    assert "docker compose up greenbone-feed-sync" in README
    assert "greenbone-feed-sync --type gvmd-data" in README
    normalized_readme = " ".join(README.split())
    assert "subsequent synchronizations only fetch deltas" in normalized_readme
