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
