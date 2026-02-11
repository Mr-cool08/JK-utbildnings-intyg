# Copyright (c) Liam Suorsa
import app


def _admin_client():
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess["admin_logged_in"] = True
        sess["admin_username"] = "loggadmin"
        sess["csrf_token"] = "test-csrf-token"
    return client


def test_admin_client_log_records_warning(_empty_db):
    client = _admin_client()
    payload = {
        "message": "Svarade inte med JSON.",
        "context": "Testlogg",
        "url": "https://example.test/admin/api/ansokningar",
        "status": 502,
        "details": {"contentType": "text/html"},
    }
    response = client.post("/admin/api/klientlogg", json=payload, headers={"X-CSRF-Token": "test-csrf-token"})

    assert response.status_code == 200
    assert response.get_json()["status"] == "success"


def test_admin_client_log_rejects_invalid_payload(_empty_db):
    client = _admin_client()

    response = client.post(
        "/admin/api/klientlogg",
        data="invalid",
        content_type="text/plain",
        headers={"X-CSRF-Token": "test-csrf-token"},
    )

    assert response.status_code == 400
    assert response.get_json()["status"] == "error"


def test_admin_client_log_rejects_missing_csrf(_empty_db):
    client = _admin_client()

    response = client.post("/admin/api/klientlogg", json={"message": "test"})

    assert response.status_code == 403
    body = response.get_json()
    assert body["status"] == "error"
    assert body["message"] == "Ogiltig CSRF-token."

# Copyright (c) Liam Suorsa
