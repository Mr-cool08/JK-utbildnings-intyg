from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import mean
from time import perf_counter

import pytest

import app
import functions
from course_categories import COURSE_CATEGORIES


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    index = int((len(sorted_values) - 1) * (percentile / 100))
    return sorted_values[index]


def _run_concurrent_requests(total_requests: int, workers: int, request_fn):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(request_fn, request_id) for request_id in range(total_requests)]
        for future in as_completed(futures):
            results.append(future.result())
    return results


def _build_user_session(client, personnummer_hash: str, personnummer_raw: str) -> None:
    with client.session_transaction() as session_data:
        session_data["user_logged_in"] = True
        session_data["personnummer"] = personnummer_hash
        session_data["personnummer_raw"] = personnummer_raw
        session_data["username"] = "Belastningstest Användare"


@pytest.mark.slow
def test_load_public_routes_high_traffic_stays_available(empty_db):
    paths = ["/", "/ansok", "/pris", "/login", "/foretagskonto/login"]
    total_requests = 600
    workers = 60

    # Warmup to avoid counting initial template/render setup in latency metrics.
    with app.app.test_client() as warmup_client:
        for path in paths:
            warmup_response = warmup_client.get(path)
            assert warmup_response.status_code == 200

    def _request(request_id: int) -> dict[str, object]:
        path = paths[request_id % len(paths)]
        started = perf_counter()
        try:
            with app.app.test_client() as client:
                started = perf_counter()
                response = client.get(path)
                duration = perf_counter() - started
            return {
                "ok": response.status_code == 200,
                "duration": duration,
                "status": response.status_code,
                "path": path,
            }
        except Exception as exc:  # pragma: no cover - defensiv fallback
            duration = perf_counter() - started
            return {
                "ok": False,
                "duration": duration,
                "status": "exception",
                "path": path,
                "error": str(exc),
            }

    results = _run_concurrent_requests(
        total_requests=total_requests, workers=workers, request_fn=_request
    )
    failures = [result for result in results if not result["ok"]]
    durations = [float(result["duration"]) for result in results]

    success_ratio = (len(results) - len(failures)) / len(results)
    assert success_ratio >= 0.995, (
        f"För låg tillgänglighet under belastning: {success_ratio:.3%} lyckade anrop "
        f"({len(failures)} fel av {len(results)})."
    )
    assert _percentile(durations, 95) < 1.8, (
        f"P95-svarstid för publika routes är för hög: {_percentile(durations, 95):.3f}s"
    )
    assert _percentile(durations, 99) < 3.0, (
        f"P99-svarstid för publika routes är för hög: {_percentile(durations, 99):.3f}s"
    )


@pytest.mark.slow
def test_stress_mixed_authenticated_traffic_handles_burst_load(user_db):
    personnummer_raw = "9001011234"
    personnummer_hash = functions.hash_value(personnummer_raw)
    categories = [slug for slug, _label in COURSE_CATEGORIES]

    with user_db.begin() as conn:
        for idx in range(80):
            conn.execute(
                functions.user_pdfs_table.insert().values(
                    personnummer=personnummer_hash,
                    filename=f"stress-{idx}.pdf",
                    content=b"%PDF-1.4 stress",
                    categories=categories[idx % len(categories)],
                )
            )

    with user_db.connect() as conn:
        pdf_ids = [
            row.id
            for row in conn.execute(
                functions.user_pdfs_table.select().where(
                    functions.user_pdfs_table.c.personnummer == personnummer_hash
                )
            ).fetchall()
        ]

    assert pdf_ids

    # Shared CI runners struggle with this route mix at very high concurrency.
    # Keep it as a burst test while avoiding flaky scheduler/DB lock artifacts.
    total_requests = 360
    workers = 30

    # Warmup to avoid counting initial template/setup overhead in latency metrics.
    with app.app.test_client() as warmup_client:
        _build_user_session(warmup_client, personnummer_hash, personnummer_raw)
        dashboard_response = warmup_client.get("/dashboard")
        assert dashboard_response.status_code == 200
        sample_pdf_response = warmup_client.get(f"/my_pdfs/{pdf_ids[0]}")
        assert sample_pdf_response.status_code == 200

    def _request(request_id: int) -> dict[str, object]:
        started = perf_counter()
        try:
            with app.app.test_client() as client:
                _build_user_session(client, personnummer_hash, personnummer_raw)
                if request_id % 4 == 0:
                    path = f"/my_pdfs/{pdf_ids[request_id % len(pdf_ids)]}"
                    started = perf_counter()
                    response = client.get(path)
                    duration = perf_counter() - started
                    ok = response.status_code == 200 and response.headers.get(
                        "Content-Type", ""
                    ).startswith("application/pdf")
                else:
                    path = "/dashboard"
                    started = perf_counter()
                    response = client.get(path)
                    duration = perf_counter() - started
                    ok = (
                        response.status_code == 200
                        and b"H\xc3\xa4r \xc3\xa4r dina intyg." in response.get_data()
                    )
            return {"ok": ok, "duration": duration, "status": response.status_code, "path": path}
        except Exception as exc:  # pragma: no cover - defensiv fallback
            duration = perf_counter() - started
            return {
                "ok": False,
                "duration": duration,
                "status": "exception",
                "path": "internal",
                "error": str(exc),
            }

    results = _run_concurrent_requests(
        total_requests=total_requests, workers=workers, request_fn=_request
    )
    failures = [result for result in results if not result["ok"]]
    durations = [float(result["duration"]) for result in results]

    success_ratio = (len(results) - len(failures)) / len(results)
    assert success_ratio >= 0.99, (
        f"För låg lyckandegrad för autentiserad trafik: {success_ratio:.3%} "
        f"({len(failures)} fel av {len(results)})."
    )
    assert mean(durations) < 4.0, (
        f"Genomsnittlig svarstid för autentiserad trafik är för hög: {mean(durations):.3f}s"
    )
    assert _percentile(durations, 95) < 8.0, (
        f"P95-svarstid för autentiserad trafik är för hög: {_percentile(durations, 95):.3f}s"
    )
    assert _percentile(durations, 99) < 10.0, (
        f"P99-svarstid för autentiserad trafik är för hög: {_percentile(durations, 99):.3f}s"
    )


# Copyright (c) Liam Suorsa and Mika Suorsa