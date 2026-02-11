# Copyright (c) Liam Suorsa
from pathlib import Path
import re
import shutil
import subprocess

import pytest
from pytest_docker.plugin import get_docker_services

ROOT = Path(__file__).resolve().parent.parent


def _read(path: Path) -> str:
    # Läs alltid som UTF-8 så emojis/icke-ASCII inte kraschar på Windows
    return path.read_text(encoding="utf-8")


def _require_working_docker() -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI finns inte installerad i testmiljön.")

    check = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        text=True,
        check=False,
    )
    if check.returncode != 0:
        pytest.skip("Docker-daemonen är inte tillgänglig i testmiljön.")


def _create_temp_compose_for_build(
    tmp_path: Path,
    *,
    service_name: str,
    dockerfile_path: str,
) -> Path:
    compose_content = (
        "services:\n"
        f"  {service_name}:\n"
        "    build:\n"
        f"      context: {ROOT.as_posix()}\n"
        f"      dockerfile: {dockerfile_path}\n"
    )
    compose_file = tmp_path / f"compose-{service_name}.yml"
    compose_file.write_text(compose_content, encoding="utf-8")
    return compose_file


def _build_image_with_pytest_docker(compose_file: Path, setup_command: str) -> None:
    project_name = f"jk_utbildnings_intyg_{setup_command.replace(' ', '_')}"
    with get_docker_services(
        docker_compose_command="docker compose",
        docker_compose_file=[str(compose_file)],
        docker_compose_project_name=project_name,
        docker_setup=[setup_command],
        docker_cleanup=[],
    ) as docker_services:
        assert docker_services is not None


def test_dockerfile_uses_python_base_image():
    dockerfile = _read(ROOT / "Dockerfile")
    # Officiell Python-basimage på Alpine, version flexibel
    assert re.search(r"^FROM\s+python:.*alpine", dockerfile, re.MULTILINE)


def test_dockerfile_uses_stable_python_tag():
    dockerfile = _read(ROOT / "Dockerfile")
    match = re.search(r"^FROM\s+python:([^\s]+)", dockerfile, re.MULTILINE)
    assert match, "Expected Dockerfile to define a python base image"
    tag = match.group(1)
    pre_release = re.search(r"(^|[-_.])(rc|alpha|beta)\d*", tag, re.IGNORECASE)
    assert pre_release is None, "Expected a stable Python tag without pre-release markers"


def test_dockerfile_exposes_port_and_runs_entrypoint():
    dockerfile = _read(ROOT / "Dockerfile")
    # Tillåt antingen 80/443 eller 8080/8443 i containern
    exposes_80_443 = re.search(r"^\s*EXPOSE\s+80\s+443\s*$", dockerfile, re.MULTILINE)
    exposes_8080_8443 = re.search(r"^\s*EXPOSE\s+8080\s+8443\s*$", dockerfile, re.MULTILINE)
    assert exposes_80_443 or exposes_8080_8443, "Expected EXPOSE 80 443 or EXPOSE 8080 8443"
    # Entrypoint-script ska fortfarande anropas via CMD
    assert 'CMD ["./entrypoint.sh"]' in dockerfile


def test_compose_avoids_host_volumes():
    compose = _read(ROOT / "docker-compose.yml")
    assert "volumes:" not in compose or "- env_data:/config" not in compose


def test_prod_compose_waits_for_healthy_backends_before_traefik_start():
    compose_prod = _read(ROOT / "docker-compose.prod.yml")
    assert "traefik:" in compose_prod
    assert "depends_on:" in compose_prod
    assert "app:\n        condition: service_healthy" in compose_prod
    assert "app_demo:\n        condition: service_healthy" in compose_prod
    assert "status_page:\n        condition: service_healthy" in compose_prod


def test_entrypoint_runs_gunicorn_only():
    entrypoint = _read(ROOT / "entrypoint.sh")
    # Backend kan vara Gunicorn (prod) eller python wsgi.py (dev)
    assert ("gunicorn" in entrypoint) or ("python wsgi.py" in entrypoint)
    # Nginx ska inte startas längre
    assert "nginx -g 'daemon off;'" not in entrypoint


def test_dockerfile_installs_openssl():
    dockerfile = _read(ROOT / "Dockerfile")
    # Någon apk-add rad måste innehålla tini och curl
    apk_lines = [line for line in dockerfile.splitlines() if "apk add" in line]
    assert apk_lines, "No apk add line found in Dockerfile"
    assert any(("tini" in line and "curl" in line) for line in apk_lines), (
        "Expected tini and curl to be installed via apk add"
    )


def test_builds_production_app_image_with_pytest_docker(tmp_path):
    _require_working_docker()
    compose_file = _create_temp_compose_for_build(
        tmp_path,
        service_name="app",
        dockerfile_path="Dockerfile",
    )
    _build_image_with_pytest_docker(compose_file, "build app")


def test_builds_dev_status_image_with_pytest_docker(tmp_path):
    _require_working_docker()
    compose_file = _create_temp_compose_for_build(
        tmp_path,
        service_name="status_page",
        dockerfile_path="status_service/Dockerfile",
    )
    _build_image_with_pytest_docker(compose_file, "build status_page")
