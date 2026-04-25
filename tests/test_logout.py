# Copyright (c) Liam Suorsa and Mika Suorsa
import app


def test_logout_clears_user_session(user_db):
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
        with client.session_transaction() as sess:
            assert sess.get("user_logged_in")
        client.get("/logout")
        with client.session_transaction() as sess:
            assert "user_logged_in" not in sess
            assert "personnummer" not in sess


def test_logout_clears_admin_session(user_db):
    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        client.get("/logout")
        with client.session_transaction() as sess:
            assert "admin_logged_in" not in sess
