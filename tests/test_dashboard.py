# Copyright (c) Liam Suorsa and Mika Suorsa
from flask import get_flashed_messages

import app
import functions
from course_categories import COURSE_CATEGORIES


def test_dashboard_shows_only_user_pdfs(user_db):
    engine = user_db
    own_hash = functions.hash_value("9001011234")
    other_hash = functions.hash_value("0001011234")

    with engine.begin() as conn:
        conn.execute(
            functions.user_pdfs_table.insert(),
            [
                {
                    "personnummer": own_hash,
                    "filename": "own.pdf",
                    "content": b"%PDF-1.4 own",
                    "categories": COURSE_CATEGORIES[0][0],
                },
                {
                    "personnummer": other_hash,
                    "filename": "other.pdf",
                    "content": b"%PDF-1.4 other",
                    "categories": COURSE_CATEGORIES[1][0],
                },
            ],
        )

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["csrf_token"] = "test-token"
        client.post(
            "/login",
            data={
                "personnummer": "9001011234",
                "password": "secret",
                "csrf_token": "test-token",
            },
        )
        response = client.get("/dashboard")
        assert b"own.pdf" in response.data
        assert b"other.pdf" not in response.data
        assert COURSE_CATEGORIES[0][1].encode() in response.data


def test_dashboard_capitalizes_first_letter_of_forename_and_surname(user_db):
    engine = user_db
    with engine.begin() as conn:
        conn.execute(
            functions.users_table.update()
            .where(functions.users_table.c.personnummer == functions.hash_value("9001011234"))
            .values(username="anna andersson")
        )

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["csrf_token"] = "test-token"
        client.post(
            "/login",
            data={
                "personnummer": "9001011234",
                "password": "secret",
                "csrf_token": "test-token",
            },
        )
        response = client.get("/dashboard")
        assert b"Hej Anna Andersson!" in response.data


def test_upload_page_formats_logged_in_user_name(user_db):
    engine = user_db
    with engine.begin() as conn:
        conn.execute(
            functions.users_table.update()
            .where(functions.users_table.c.personnummer == functions.hash_value("9001011234"))
            .values(username="anna andersson")
        )

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["csrf_token"] = "test-token"
        client.post(
            "/login",
            data={
                "personnummer": "9001011234",
                "password": "secret",
                "csrf_token": "test-token",
            },
        )
        response = client.get("/dashboard/upload")

    assert response.status_code == 200
    assert b"Hej Anna Andersson!" in response.data
    assert b"Ladda upp intyg" in response.data


def test_upload_page_uses_count_user_pdfs(monkeypatch, user_db):
    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["csrf_token"] = "test-token"
        client.post(
            "/login",
            data={
                "personnummer": "9001011234",
                "password": "secret",
                "csrf_token": "test-token",
            },
        )

        monkeypatch.setattr(app.functions, "count_user_pdfs", lambda _pnr_hash: 7)

        def _unexpected_get_user_pdfs(*_args, **_kwargs):
            raise AssertionError("get_user_pdfs ska inte användas på uppladdningssidan")

        monkeypatch.setattr(app.functions, "get_user_pdfs", _unexpected_get_user_pdfs)
        response = client.get("/dashboard/upload")

    assert response.status_code == 200
    assert b"7 intyg i arkivet" in response.data


def test_request_entity_too_large_redirects_dashboard_upload_prefix(empty_db):
    with app.app.test_request_context("/dashboard/ladda-upp/bilagor", method="POST"):
        response = app.request_entity_too_large(None)
        flashes = get_flashed_messages(with_categories=True)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard/upload")
    assert flashes == [("error", app.UPLOAD_TOO_LARGE_MESSAGE)]
