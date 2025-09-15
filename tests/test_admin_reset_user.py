import app
import functions


def test_admin_reset_requires_login(empty_db):
    with app.app.test_client() as client:
        response = client.get("/admin/reset-user")
    assert response.status_code == 302
    assert "/login_admin" in response.headers["Location"]


def test_admin_reset_user_success(empty_db, monkeypatch):
    reset_called = {}

    def fake_reset(email, personnummer, upload_root):
        reset_called["args"] = (email, personnummer, upload_root)
        return {
            "username": "User",
            "personnummer_hash": "hashedpnr",
            "pdf_paths": [],
        }

    send_called = {}

    def fake_send(email, link):
        send_called["args"] = (email, link)

    monkeypatch.setattr(functions, "reset_user_to_pending", fake_reset)
    monkeypatch.setattr(app, "send_creation_email", fake_send)

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.post(
            "/admin/reset-user",
            data={"email": "user@example.com", "personnummer": "19900101-1234"},
        )

    assert response.status_code == 200
    assert "En återställningslänk har skickats" in response.get_data(as_text=True)
    assert reset_called["args"][0] == "user@example.com"
    assert reset_called["args"][1] == "19900101-1234"
    assert reset_called["args"][2] == app.app.config["UPLOAD_ROOT"]
    assert send_called["args"][0] == "user@example.com"
    assert "create_user/hashedpnr" in send_called["args"][1]


def test_admin_reset_user_value_error(empty_db, monkeypatch):
    def fake_reset(*_):
        raise ValueError("Användaren hittades inte.")

    monkeypatch.setattr(functions, "reset_user_to_pending", fake_reset)

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.post(
            "/admin/reset-user",
            data={"email": "user@example.com", "personnummer": "19900101-1234"},
        )

    assert response.status_code == 200
    assert "Användaren hittades inte" in response.get_data(as_text=True)
