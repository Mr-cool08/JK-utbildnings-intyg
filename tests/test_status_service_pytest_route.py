from status_service.app import app


def test_pytest_route_returns_success_message(monkeypatch):
    class FakeProcess:
        def __init__(self, lines, returncode):
            self.stdout = iter(lines)
            self.returncode = returncode

        def wait(self):
            return self.returncode

    def fake_popen(*_args, **_kwargs):
        return FakeProcess(["testkörning\n"], 0)

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
