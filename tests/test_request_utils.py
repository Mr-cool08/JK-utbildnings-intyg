# Copyright (c) Liam Suorsa and Mika Suorsa
import threading
import time

from functions import requests as ru


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
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    headers = {"X-Forwarded-For": "203.0.113.1, 198.51.100.2"}
    dummy_request = type("DummyRequest", (), {"headers": headers, "remote_addr": "198.51.100.3"})
    monkeypatch.setattr(ru, "request", dummy_request)

    assert ru.get_request_ip() == "203.0.113.1"

    headers = {"X-Forwarded-For": "198.51.100.4"}
    dummy_request = type("DummyRequest", (), {"headers": headers, "remote_addr": "198.51.100.5"})
    monkeypatch.setattr(ru, "request", dummy_request)

    assert ru.get_request_ip() == "198.51.100.5"


def test_get_request_ip_ignores_forwarded_header_without_trusted_proxies(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "0")
    headers = {"X-Forwarded-For": "203.0.113.9"}
    dummy_request = type("DummyRequest", (), {"headers": headers, "remote_addr": "198.51.100.9"})
    monkeypatch.setattr(ru, "request", dummy_request)

    assert ru.get_request_ip() == "198.51.100.9"


def test_get_request_ip_uses_trusted_proxy_count(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "2")
    headers = {"X-Forwarded-For": "203.0.113.10, 198.51.100.10, 198.51.100.11"}
    dummy_request = type("DummyRequest", (), {"headers": headers, "remote_addr": "198.51.100.12"})
    monkeypatch.setattr(ru, "request", dummy_request)

    assert ru.get_request_ip() == "203.0.113.10"


def test_get_request_ip_falls_back_when_forwarded_chain_is_too_short(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "2")
    headers = {"X-Forwarded-For": "203.0.113.10, 198.51.100.10"}
    dummy_request = type("DummyRequest", (), {"headers": headers, "remote_addr": "198.51.100.12"})
    monkeypatch.setattr(ru, "request", dummy_request)

    assert ru.get_request_ip() == "198.51.100.12"


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


def test_register_public_submission_serializes_concurrent_access(monkeypatch):
    append_counts = []
    first_append_entered = threading.Event()
    release_append = threading.Event()

    class CoordinatedBucket:
        def __init__(self):
            self.items = []

        def __bool__(self):
            return bool(self.items)

        def __len__(self):
            return len(self.items)

        def append(self, value):
            append_counts.append(value)
            first_append_entered.set()
            release_append.wait(timeout=1)
            self.items.append(value)

        def popleft(self):
            return self.items.pop(0)

    ru._public_form_attempts.clear()
    ru._public_form_attempts["5.5.5.5"] = CoordinatedBucket()
    monkeypatch.setattr(ru, "_PUBLIC_FORM_LIMIT", 1)
    monkeypatch.setattr(ru, "_cleanup_expired_attempts", lambda now: None)
    monkeypatch.setattr(ru, "_trim_bucket", lambda bucket, now: None)
    monkeypatch.setattr(ru.time, "time", lambda: 1_000.0)

    start_barrier = threading.Barrier(3)
    results = []
    results_lock = threading.Lock()

    def worker():
        start_barrier.wait()
        result = ru.register_public_submission("5.5.5.5")
        with results_lock:
            results.append(result)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()

    start_barrier.wait()
    assert first_append_entered.wait(timeout=1)

    deadline = time.time() + 0.2
    while len(append_counts) < 2 and time.time() < deadline:
        time.sleep(0.01)

    release_append.set()

    for thread in threads:
        thread.join()

    assert sorted(results) == [False, True]
    assert len(ru._public_form_attempts["5.5.5.5"]) == 1
