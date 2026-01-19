# Copyright (c) Liam Suorsa
from status_service.app import app


def test_pytest_route_returns_success_message(monkeypatch):
    captured_calls = {}

    class FakeProcess:
        def __init__(self, lines, returncode):
            self.stdout = iter(lines)
            self.returncode = returncode

        def wait(self):
            return self.returncode

    def fake_popen(*args, **_kwargs):
        captured_calls["args"] = args
        return FakeProcess(["testkörning\n"], 0)

    monkeypatch.setattr("status_service.app.importlib.util.find_spec", lambda _name: object())
    monkeypatch.setattr("status_service.app.subprocess.Popen", fake_popen)

    app.testing = True
    with app.test_client() as client:
        response = client.get("/pytest")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == (
        "Startar pytest...\n"
        "testkörning\n"
        "Pytest klart: lyckades.\n"
    )
    assert captured_calls["args"][0][-2:] == ["-m", "pytest"]


def test_pytest_route_returns_failure_message(monkeypatch):
    captured_events = {}

    class FakeProcess:
        def __init__(self, lines, returncode):
            self.stdout = iter(lines)
            self.returncode = returncode

        def wait(self):
            return self.returncode

    def fake_popen(*_args, **_kwargs):
        return FakeProcess(["felrad\n"], 2)

    monkeypatch.setattr("status_service.app.importlib.util.find_spec", lambda _name: object())
    monkeypatch.setattr("status_service.app.subprocess.Popen", fake_popen)

    def fake_send_critical_event_email(**kwargs):
        captured_events.update(kwargs)

    monkeypatch.setattr(
        "status_service.app.critical_events.send_critical_event_email",
        fake_send_critical_event_email,
    )

    app.testing = True
    with app.test_client() as client:
        response = client.get("/pytest")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == (
        "Startar pytest...\n"
        "felrad\n"
        "Pytest misslyckades. Kritisk händelse har skickats.\n"
    )
    assert captured_events["event_type"] == "error"
    assert captured_events["title"] == "🔴 Pytest misslyckades"
    assert "Pytest-körningen misslyckades via status-tjänsten." in captured_events["description"]
    assert captured_events["error_message"] == "felrad\n"


def test_pytest_route_handles_missing_stdout(monkeypatch):
    class FakeProcess:
        def __init__(self):
            self.stdout = None
            self.returncode = 0

        def communicate(self):
            return ("utdata utan stdout\n", None)

    def fake_popen(*_args, **_kwargs):
        return FakeProcess()

    monkeypatch.setattr("status_service.app.importlib.util.find_spec", lambda _name: object())
    monkeypatch.setattr("status_service.app.subprocess.Popen", fake_popen)

    app.testing = True
    with app.test_client() as client:
        response = client.get("/pytest")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == (
        "Startar pytest...\n"
        "utdata utan stdout\n"
        "Pytest klart: lyckades.\n"
    )


def test_pytest_route_handles_missing_pytest(monkeypatch):
    monkeypatch.setattr("status_service.app.importlib.util.find_spec", lambda _name: None)

    app.testing = True
    with app.test_client() as client:
        response = client.get("/pytest")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == (
        "Startar pytest...\n"
        "Pytest saknas i miljön. Installera pytest och försök igen.\n"
    )


def test_pytest_route_handles_startup_failure(monkeypatch):
    captured_events = {}

    def fake_popen(*_args, **_kwargs):
        raise OSError("kunde inte starta")

    def fake_send_critical_event_email(**kwargs):
        captured_events.update(kwargs)

    monkeypatch.setattr("status_service.app.importlib.util.find_spec", lambda _name: object())
    monkeypatch.setattr("status_service.app.subprocess.Popen", fake_popen)
    monkeypatch.setattr(
        "status_service.app.critical_events.send_critical_event_email",
        fake_send_critical_event_email,
    )

    app.testing = True
    with app.test_client() as client:
        response = client.get("/pytest")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == (
        "Startar pytest...\n"
        "Pytest kunde inte starta. Kritisk händelse har skickats.\n"
    )
    assert captured_events["event_type"] == "error"
    assert captured_events["title"] == "🔴 Pytest kunde inte starta"
