import request_utils as ru


def test_register_public_submission_cleans_stale_attempts(monkeypatch):
    ru._public_form_attempts.clear()
    monkeypatch.setattr(ru, "_last_cleanup", 0)
    monkeypatch.setattr(ru, "_CLEANUP_INTERVAL", 0)

    start_time = 1_000.0
    monkeypatch.setattr(ru.time, "time", lambda: start_time)

    assert ru.register_public_submission("1.1.1.1")
    assert "1.1.1.1" in ru._public_form_attempts

    monkeypatch.setattr(ru.time, "time", lambda: start_time + ru._PUBLIC_FORM_WINDOW + 1)

    assert ru.register_public_submission("2.2.2.2")
    assert "1.1.1.1" not in ru._public_form_attempts


def test_register_public_submission_rate_limits(monkeypatch):
    ru._public_form_attempts.clear()
    monkeypatch.setattr(ru, "_last_cleanup", 0)

    times = iter(range(1_000, 1_000 + ru._PUBLIC_FORM_LIMIT + 2))
    monkeypatch.setattr(ru.time, "time", lambda: next(times))

    for _ in range(ru._PUBLIC_FORM_LIMIT):
        assert ru.register_public_submission("3.3.3.3")

    assert not ru.register_public_submission("3.3.3.3")


def test_get_request_ip_prefers_forwarded_header(monkeypatch):
    headers = {"X-Forwarded-For": "203.0.113.1, 198.51.100.2"}
    dummy_request = type("DummyRequest", (), {"headers": headers, "remote_addr": "198.51.100.3"})
    monkeypatch.setattr(ru, "request", dummy_request)

    assert ru.get_request_ip() == "203.0.113.1"

    headers = {"X-Forwarded-For": "198.51.100.4"}
    dummy_request = type("DummyRequest", (), {"headers": headers, "remote_addr": "198.51.100.5"})
    monkeypatch.setattr(ru, "request", dummy_request)

    assert ru.get_request_ip() == "198.51.100.4"


def test_as_bool_interpretations():
    for truthy in ["1", "true", "TRUE", " on ", "Ja", "YES"]:
        assert ru.as_bool(truthy)

    for falsy in [None, "", "0", "false", "nej", " off "]:
        assert not ru.as_bool(falsy)


def test_rate_limiting_respects_time_window_boundary(monkeypatch):
    ru._public_form_attempts.clear()
    monkeypatch.setattr(ru, "_last_cleanup", 0)

    current_time = [1_000.0]

    def fake_time():
        return current_time[0]

    monkeypatch.setattr(ru.time, "time", fake_time)

    for _ in range(ru._PUBLIC_FORM_LIMIT):
        assert ru.register_public_submission("4.4.4.4")

    current_time[0] = 1_000.0 + ru._PUBLIC_FORM_WINDOW
    assert not ru.register_public_submission("4.4.4.4")

    current_time[0] = 1_000.0 + ru._PUBLIC_FORM_WINDOW + 0.1
    assert ru.register_public_submission("4.4.4.4")
