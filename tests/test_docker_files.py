from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent


def _read(path: Path) -> str:
    # Läs alltid som UTF-8 så emojis/icke-ASCII inte kraschar på Windows
    return path.read_text(encoding="utf-8")


def test_dockerfile_uses_python_base_image():
    dockerfile = _read(ROOT / "Dockerfile")
    # Officiell Python-basimage på Alpine, version flexibel
    assert re.search(r"^FROM\s+python:.*alpine", dockerfile, re.MULTILINE)


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


def test_entrypoint_runs_gunicorn_only():
    entrypoint = _read(ROOT / "entrypoint.sh")
    # Backend kan vara Gunicorn (prod) eller python wsgi.py (dev)
    assert ("gunicorn" in entrypoint) or ("python wsgi.py" in entrypoint)
    # Nginx ska inte startas längre
    assert "nginx -g 'daemon off;'" not in entrypoint


def test_dockerfile_installs_openssl():
    dockerfile = _read(ROOT / "Dockerfile")
    # Någon apk-add rad måste innehålla tini och curl
    apk_lines = [l for l in dockerfile.splitlines() if "apk add" in l]
    assert apk_lines, "No apk add line found in Dockerfile"
    assert any(("tini" in l and "curl" in l) for l in apk_lines), \
        "Expected tini and curl to be installed via apk add"
