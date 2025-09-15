import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app  # noqa: E402
import functions  # noqa: E402


def test_verify_certificate_caching_and_message(empty_db, monkeypatch):
    functions.verify_certificate.cache_clear()
    assert not functions.verify_certificate("19900101-1234")

    def fail_get_engine():
        raise AssertionError("verify_certificate should use cached value")

    monkeypatch.setattr(functions, "get_engine", fail_get_engine)
    assert not functions.verify_certificate("19900101-1234")

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.get("/verify_certificate/19900101-1234")
        assert response.status_code == 404
        assert "inte verifierat" in response.get_data(as_text=True).lower()
