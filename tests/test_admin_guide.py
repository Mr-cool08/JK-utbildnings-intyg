# Copyright (c) Liam Suorsa
from pathlib import Path

import app


def _admin_client():
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["admin_logged_in"] = True
    return client


def test_admin_guide_requires_login():
    client = app.app.test_client()
    response = client.get("/admin/guide")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login_admin")


def test_admin_guide_shows_admin_markdown():
    guide_path = Path(app.__file__).resolve().parent / "admin.md"
    expected_heading = "Hur man administrerar systemet"
    assert expected_heading in guide_path.read_text(encoding="utf-8")

    with _admin_client() as client:
        response = client.get("/admin/guide")
    assert response.status_code == 200
    assert expected_heading in response.get_data(as_text=True)

# Copyright (c) Liam Suorsa
