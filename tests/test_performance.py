import time
from statistics import mean

import app
import functions
from course_categories import COURSE_CATEGORIES


def _client():
    return app.app.test_client()


def _measure_get_times(client, path, iterations=3):
    durations = []
    for _ in range(iterations):
        start = time.perf_counter()
        response = client.get(path)
        durations.append(time.perf_counter() - start)
        assert response.status_code == 200
    return durations


def _login_user(client):
    with client.session_transaction() as session:
        session["csrf_token"] = "test-token"
    response = client.post(
        "/login",
        data={
            "personnummer": "9001011234",
            "password": "secret",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302


def test_public_pages_render_within_response_budget(empty_db):
    routes_and_max_seconds = {
        "/": 0.90,
        "/ansok": 0.90,
        "/ansok/standardkonto": 1.00,
        "/ansok/foretagskonto": 1.00,
        "/pris": 0.90,
        "/login": 0.90,
        "/foretagskonto/login": 0.90,
    }

    with _client() as client:
        # Warm up template rendering before measuring.
        for path in routes_and_max_seconds:
            warmup_response = client.get(path)
            assert warmup_response.status_code == 200

        for path, max_seconds in routes_and_max_seconds.items():
            durations = _measure_get_times(client, path, iterations=3)
            assert mean(durations) < 0.60, (
                f"Genomsnittlig svarstid för {path} var {mean(durations):.3f}s (budget 0.600s)"
            )
            assert max(durations) < max_seconds, (
                f"Långsam route {path}: max {max(durations):.3f}s (budget {max_seconds:.3f}s)"
            )


def test_dashboard_with_many_certificates_renders_within_budget(user_db):
    personnummer_hash = functions.hash_value("9001011234")
    categories = [slug for slug, _ in COURSE_CATEGORIES]

    rows = []
    for index in range(200):
        rows.append(
            {
                "personnummer": personnummer_hash,
                "filename": f"intyg-{index}.pdf",
                "content": b"%PDF-1.4 prestanda",
                "categories": categories[index % len(categories)],
            }
        )

    with user_db.begin() as conn:
        conn.execute(functions.user_pdfs_table.insert(), rows)

    with _client() as client:
        _login_user(client)

        warmup_response = client.get("/dashboard")
        assert warmup_response.status_code == 200

        durations = _measure_get_times(client, "/dashboard", iterations=3)

    assert mean(durations) < 1.20, f"Dashboard genomsnitt {mean(durations):.3f}s överskrider 1.200s"
    assert max(durations) < 2.50, f"Dashboard max {max(durations):.3f}s överskrider 2.500s"


def test_dashboard_repeated_requests_remain_stable(user_db):
    with _client() as client:
        _login_user(client)

        warmup_response = client.get("/dashboard")
        assert warmup_response.status_code == 200

        durations = _measure_get_times(client, "/dashboard", iterations=8)

    assert mean(durations) < 0.70, (
        f"Dashboard genomsnitt vid upprepade anrop var {mean(durations):.3f}s (budget 0.700s)"
    )
    assert max(durations) < 1.20, (
        f"Dashboard svarstidspik var {max(durations):.3f}s (budget 1.200s)"
    )


# Copyright (c) Liam Suorsa and Mika Suorsa