import app


def test_forgot_password_notifies_support(empty_db, monkeypatch):
    called = {}

    def fake_send_support_email(pnr):
        called["pnr"] = pnr

    monkeypatch.setattr(app, "send_support_email", fake_send_support_email)

    with app.app.test_client() as client:
        response = client.post(
            "/login",
            data={"personnummer": "19900101-1234", "action": "forgot-password"},
        )

    assert response.status_code == 200
    assert b"Supporten har informerats" in response.data
    assert called["pnr"] == "19900101-1234"


def test_forgot_password_invalid_personnummer(empty_db, monkeypatch):
    def fake_send_support_email(_):
        raise ValueError("Ogiltigt personnummerformat.")

    monkeypatch.setattr(app, "send_support_email", fake_send_support_email)

    with app.app.test_client() as client:
        response = client.post(
            "/login",
            data={"personnummer": "invalid", "action": "forgot-password"},
        )

    assert response.status_code == 200
    assert b"Ogiltigt personnummerformat" in response.data
