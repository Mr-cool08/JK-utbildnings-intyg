from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_uses_python_base_image():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert re.search(r"^FROM python:3\.14\.0rc2-alpine3\.22", dockerfile, re.MULTILINE)


def test_dockerfile_exposes_port_and_runs_entrypoint():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "EXPOSE 8080" in dockerfile
    assert 'CMD ["./entrypoint.sh"]' in dockerfile


def test_compose_maps_port_and_sets_db_path():
    compose = (ROOT / "docker-compose.yml").read_text()
    assert re.search(r"-\s*\"80:8080\"", compose)
    assert "DB_PATH: /data/database.db" in compose


def test_compose_mounts_config_volume():
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "- env_data:/config" in compose
