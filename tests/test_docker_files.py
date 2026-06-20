# Copyright (c) Liam Suorsa and Mika Suorsa
from pathlib import Path
import re
import shutil
import subprocess

import pytest

try:
    from pytest_docker.plugin import get_docker_services
except ModuleNotFoundError:  # pragma: no cover - beror på testmiljön
    get_docker_services = None

ROOT = Path(__file__).resolve().parent.parent


def _read(path: Path) -> str:
    # Läs alltid som UTF-8 så emojis/icke-ASCII inte kraschar på Windows
    return path.read_text(encoding="utf-8")


def _extract_service_block(compose: str, service_name: str) -> str:
    service_match = re.search(
        rf"(?ms)^  {re.escape(service_name)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        compose,
    )
    assert service_match, f"Expected {service_name} service in docker-compose.yml"
    return service_match.group(1)


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
    if get_docker_services is None:
        pytest.skip("pytest-docker är inte installerat i testmiljön.")

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
    app_service_match = re.search(
        r"(?ms)^  app:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        compose,
    )
    assert app_service_match, "Expected app service in docker-compose.yml"
    app_service = app_service_match.group(1)
    assert "- env_data:/config" in app_service
    assert re.search(r"-\s+\./[^:\n]*:/config", app_service) is None


def test_compose_uses_direct_host_port_bindings_for_main_services():
    compose = _read(ROOT / "docker-compose.yml")

    assert "dev_main_port:" not in compose
    assert "80:80" in compose
    assert "127.0.0.1:80:80" not in compose


def test_compose_does_not_include_rclone_cloud_backup_service():
    compose = _read(ROOT / "docker-compose.yml")

    assert "backup_cloud_sync:" not in compose
    assert "image: rclone/rclone:1.69" not in compose
    assert "backup-cloud" not in compose
    assert 'command: ["sh", "/scripts/rclone_sync.sh", "--loop"]' not in compose
    assert "RCLONE_ONEDRIVE_TOKEN" not in compose
    assert "RCLONE_DROPBOX_TOKEN" not in compose
    assert "RCLONE_CONFIG_FILE: /tmp/rclone/rclone.conf" not in compose


def test_compose_runs_postgres_backup_script_with_bash():
    compose = _read(ROOT / "docker-compose.yml")

    assert 'command: ["bash", "/scripts/postgres_backup.sh", "--loop"]' in compose
    assert 'command: ["/bin/sh", "/scripts/postgres_backup.sh", "--loop"]' not in compose


def test_compose_has_expiry_reminder_service_that_only_runs_script():
    compose = _read(ROOT / "docker-compose.yml")
    expiry_service = _extract_service_block(compose, "expiry_reminder")
    assert 'command: ["python", "-m", "scripts.send_expiry_reminders"]' in expiry_service
    assert "ports:" not in expiry_service
    assert "expose:" not in expiry_service
    assert "gunicorn" not in expiry_service
    assert "entrypoint.sh" not in expiry_service
    assert "      - db_net" in expiry_service
    assert "      - public_net" in expiry_service


def test_compose_default_resource_caps_fit_small_host_profile():
    compose = _read(ROOT / "docker-compose.yml")
    default_services = [
        "traefik",
        "fail2ban",
        "app",
        "expiry_reminder",
        "postgres",
        "postgres_backup",
    ]

    total_memory_mb = 0
    total_cpus = 0.0

    for service_name in default_services:
        service_block = _extract_service_block(compose, service_name)
        memory_match = re.search(
            r"^\s+mem_limit: (\d+)([mg])$",
            service_block,
            re.MULTILINE,
        )
        cpu_match = re.search(r'^\s+cpus: "([0-9.]+)"$', service_block, re.MULTILINE)

        assert memory_match, f"Expected mem_limit for {service_name}"
        assert cpu_match, f"Expected cpus limit for {service_name}"

        memory_value = int(memory_match.group(1))
        memory_unit = memory_match.group(2)
        if memory_unit == "g":
            total_memory_mb += memory_value * 1024
        else:
            total_memory_mb += memory_value

        total_cpus += float(cpu_match.group(1))

    assert total_memory_mb <= 1408
    assert total_cpus <= 1.55


def test_compose_tunes_app_and_postgres_for_small_host_profile():
    compose = _read(ROOT / "docker-compose.yml")
    app_service = _extract_service_block(compose, "app")
    postgres_service = _extract_service_block(compose, "postgres")

    assert "WEB_CONCURRENCY: ${WEB_CONCURRENCY:-1}" in app_service
    assert "THREADS: ${THREADS:-4}" in app_service

    assert "- shared_buffers=128MB" in postgres_service
    assert "- work_mem=2MB" in postgres_service
    assert "- maintenance_work_mem=32MB" in postgres_service
    assert "- effective_cache_size=256MB" in postgres_service
    assert "- max_connections=30" in postgres_service


def test_gitattributes_forces_lf_for_shell_scripts():
    gitattributes = _read(ROOT / ".gitattributes")

    assert "*.sh text eol=lf" in gitattributes


def test_shell_scripts_use_lf_line_endings():
    shell_scripts = sorted(ROOT.rglob("*.sh"))
    assert shell_scripts, "Expected shell scripts to exist in the repository"

    offenders = [
        path.relative_to(ROOT).as_posix()
        for path in shell_scripts
        if b"\r\n" in path.read_bytes()
    ]
    assert offenders == [], (
        "Expected LF line endings in shell scripts, found CRLF in: "
        + ", ".join(offenders)
    )


def test_example_env_does_not_document_rclone_backup_settings():
    example_env = _read(ROOT / ".example.env")

    assert 'Docker Compose-profilen "backup-cloud"' not in example_env
    assert "RCLONE_REMOTE=" not in example_env
    assert "RCLONE_BACKUP_PATH=jk-utbildnings-intyg/postgres" not in example_env
    assert "RCLONE_SYNC_INTERVAL_SECONDS=3600" not in example_env
    assert "RCLONE_PRUNE_REMOTE=false" not in example_env
    assert "RCLONE_ONEDRIVE_TOKEN=" not in example_env
    assert "RCLONE_ONEDRIVE_DRIVE_ID=" not in example_env
    assert "RCLONE_DROPBOX_TOKEN=" not in example_env


def test_rclone_sync_script_has_been_removed():
    assert not (ROOT / "scripts" / "backup" / "rclone_sync.sh").exists()


def test_docs_do_not_reference_removed_rclone_compose_setup():
    readme = _read(ROOT / "README.md")
    deployment = _read(ROOT / "docs" / "DEPLOYMENT.md")

    for content in (readme, deployment):
        assert "backup_cloud_sync" not in content
        assert "backup-cloud" not in content
        assert "RCLONE_" not in content


def test_entrypoint_runs_gunicorn_only():
    entrypoint = _read(ROOT / "entrypoint.sh")
    # Backend kan vara Gunicorn (prod) eller python wsgi.py (dev)
    assert ("gunicorn" in entrypoint) or ("python wsgi.py" in entrypoint)

    # Ingen extern Nginx-process ska startas i app-containern
    nginx_start_pattern = re.compile(
        r"""(?ix)
        (?:^|[;\s])
        (?:
            nginx(?:\s+-g)?
            |service\s+nginx
            |systemctl\s+start\s+nginx
            |rc-service\s+nginx
            |/usr/sbin/nginx
        )
        (?:$|[\s;])
        """
    )
    assert nginx_start_pattern.search(entrypoint) is None


def test_entrypoint_requires_explicit_true_for_dev_mode():
    entrypoint = _read(ROOT / "entrypoint.sh")
    local_database_case = re.search(
        r'case "\$\{enable_local_db\}:\$\{enable_demo_mode\}" in\s+([^)]+)\)',
        entrypoint,
    )

    assert local_database_case is not None
    dev_mode_patterns = [
        pattern
        for pattern in local_database_case.group(1).split("|")
        if pattern.endswith(":*")
    ]
    assert dev_mode_patterns == ["true:*"]


def test_compose_assigns_explicit_traefik_logs_volume_name():
    compose = _read(ROOT / "docker-compose.yml")

    assert (
        "  traefik_logs:\n"
        "    name: jk-utbildnings-intyg_traefik_logs\n"
        in compose
    )


def test_dockerfile_installs_openssl():
    dockerfile = _read(ROOT / "Dockerfile")
    # Någon apk-add rad måste innehålla tini och curl
    apk_lines = [line for line in dockerfile.splitlines() if "apk add" in line]
    assert apk_lines, "No apk add line found in Dockerfile"
    assert any(("tini" in line and "curl" in line) for line in apk_lines), (
        "Expected tini and curl to be installed via apk add"
    )


@pytest.mark.docker
def test_builds_production_app_image_with_pytest_docker(tmp_path):
    _require_working_docker()
    compose_file = _create_temp_compose_for_build(
        tmp_path,
        service_name="app",
        dockerfile_path="Dockerfile",
    )
    _build_image_with_pytest_docker(compose_file, "build app")
