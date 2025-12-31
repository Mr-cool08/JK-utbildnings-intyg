import io
import pytest

import app
import functions


@pytest.fixture
def client(monkeypatch, tmp_path):
    # Isolera databasen och ge en testklient.
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'app.db'}")
    functions.reset_engine()
    functions.create_database()
    app.app.config.update(TESTING=True, SECRET_KEY="test")
    return app.app.test_client()


def test_start_demo_reset_scheduler(monkeypatch):
    calls = []
    captured_target = {}

    class FakeThread:
        def __init__(self, target, daemon, name):
            captured_target["target"] = target
            self.daemon = daemon
            self.name = name
            self.started = False

        def start(self):
            self.started = True

    monkeypatch.setattr(app.threading, "Thread", FakeThread)
    monkeypatch.setattr(app.functions, "reset_demo_database", lambda defaults: calls.append(defaults))

    demo_defaults = {"user_email": "demo@example.com"}
    app._start_demo_reset_scheduler(app.app, demo_defaults)

    assert captured_target["target"]
    # Kör loopen en gång och avbryt via SystemExit.
    monkeypatch.setattr(app.time, "sleep", lambda _seconds: (_ for _ in ()).throw(SystemExit()))
    with pytest.raises(SystemExit):
        captured_target["target"]()
    assert calls == [demo_defaults]

    # Hantera fel vid återställning.
    monkeypatch.setattr(app.functions, "reset_demo_database", lambda _defaults: (_ for _ in ()).throw(RuntimeError("fail")))
    with pytest.raises(SystemExit):
        captured_target["target"]()


def test_create_user_routes(monkeypatch, client):
    monkeypatch.setattr(app.functions, "user_create_user", lambda password, pnr_hash: None)
    monkeypatch.setattr(app.functions, "check_pending_user_hash", lambda value: value == "known")

    resp = client.get("/create_user/known")
    assert resp.status_code == 200

    resp_missing = client.get("/create_user/unknown")
    assert resp_missing.status_code == 200
    assert "hittades inte" in resp_missing.text

    resp_post = client.post("/create_user/known", data={"password": "secret"})
    assert resp_post.status_code == 302
    assert resp_post.headers["Location"].endswith("/login")


def test_supervisor_create_branches(monkeypatch, client):
    # Parolaerna matchar inte.
    resp_mismatch = client.post(
        "/foretagskonto/skapa/testhash",
        data={"password": "a", "confirm": "b"},
    )
    assert "matcha" in resp_mismatch.text

    # Aktivering misslyckas.
    monkeypatch.setattr(app.functions, "supervisor_activate_account", lambda *_: False)
    resp_failed = client.post(
        "/foretagskonto/skapa/testhash",
        data={"password": "a", "confirm": "a"},
    )
    assert "kunde inte aktiveras" in resp_failed.text

    # Felaktiga värden kastar undantag.
    monkeypatch.setattr(app.functions, "supervisor_activate_account", lambda *_: (_ for _ in ()).throw(ValueError("fel")))
    resp_error = client.post(
        "/foretagskonto/skapa/testhash",
        data={"password": "a", "confirm": "a"},
    )
    assert "fel" in resp_error.text

    # Inget väntande konto hittas.
    monkeypatch.setattr(app.functions, "check_pending_supervisor_hash", lambda *_: False)
    resp_invalid = client.get("/foretagskonto/skapa/absent")
    assert resp_invalid.status_code == 200

    # Lyckad aktivering leder till redirect.
    monkeypatch.setattr(app.functions, "check_pending_supervisor_hash", lambda value: True)
    monkeypatch.setattr(app.functions, "supervisor_activate_account", lambda *_: True)
    resp_success = client.post(
        "/foretagskonto/skapa/ok",
        data={"password": "abc", "confirm": "abc"},
    )
    assert resp_success.status_code == 302
    assert resp_success.headers["Location"].endswith("/foretagskonto/login")

    # GET för väntande konto.
    resp_pending = client.get("/foretagskonto/skapa/ok")
    assert resp_pending.status_code == 200


def test_supervisor_login_paths(monkeypatch, client):
    # Inga uppgifter inskickade.
    resp_missing = client.post("/foretagskonto/login", data={"orgnr": "", "password": ""})
    assert "ogiltiga" in resp_missing.text.lower()

    # Ogiltigt organisationsnummer.
    monkeypatch.setattr(app.functions, "validate_orgnr", lambda _value: (_ for _ in ()).throw(ValueError("invalid")))
    resp_invalid_org = client.post(
        "/foretagskonto/login", data={"orgnr": "abc", "password": "pw"}
    )
    assert "ogiltiga" in resp_invalid_org.text.lower()

    # Konto saknas.
    monkeypatch.setattr(app.functions, "validate_orgnr", lambda value: value)
    monkeypatch.setattr(app.functions, "get_supervisor_login_details_for_orgnr", lambda _orgnr: None)
    resp_missing_acc = client.post(
        "/foretagskonto/login", data={"orgnr": "123", "password": "pw"}
    )
    assert "ogiltiga" in resp_missing_acc.text.lower()

    # Felaktigt lösenord.
    monkeypatch.setattr(
        app.functions,
        "get_supervisor_login_details_for_orgnr",
        lambda _orgnr: {"email": "e@example.com", "email_hash": "hash"},
    )
    monkeypatch.setattr(app.functions, "verify_supervisor_credentials", lambda *_: False)
    resp_bad_pw = client.post(
        "/foretagskonto/login", data={"orgnr": "123", "password": "pw"}
    )
    assert "ogiltiga" in resp_bad_pw.text.lower()

    # Ogiltig kontokonfiguration kastar fel.
    monkeypatch.setattr(
        app.functions,
        "verify_supervisor_credentials",
        lambda *_: (_ for _ in ()).throw(ValueError("felaktig konfiguration")),
    )
    resp_config_error = client.post(
        "/foretagskonto/login", data={"orgnr": "123", "password": "pw"}
    )
    assert "ogiltiga" in resp_config_error.text.lower()

    # Lyckad inloggning.
    monkeypatch.setattr(app.functions, "verify_supervisor_credentials", lambda *_: True)
    monkeypatch.setattr(app.functions, "get_supervisor_name_by_hash", lambda _hash: "Bossen")
    resp_ok = client.post(
        "/foretagskonto/login", data={"orgnr": "123", "password": "pw"}
    )
    assert resp_ok.status_code == 302
    assert resp_ok.headers["Location"].endswith("/foretagskonto")


def _login_user(session_store):
    session_store["user_logged_in"] = True
    session_store["personnummer"] = "hash"
    session_store["personnummer_raw"] = "9001011234"


def test_user_upload_and_dashboard_actions(monkeypatch, client):
    monkeypatch.setattr(app, "validate_csrf_token", lambda allow_if_absent=False: True)
    monkeypatch.setattr(app, "save_pdf_for_user", lambda *args, **kwargs: None)
    monkeypatch.setattr(app.functions, "list_user_link_requests", lambda *_: [])
    monkeypatch.setattr(app.functions, "list_user_supervisor_connections", lambda *_: [])
    monkeypatch.setattr(app.ensure_csrf_token, "__call__", lambda *_args, **_kwargs: "token")

    with client.session_transaction() as sess:
        _login_user(sess)
        sess["username"] = "testare"

    resp_upload = client.post(
        "/dashboard/ladda-upp",
        data={"category": "arbetsmiljo", "certificate": (io.BytesIO(b"pdf"), "intyg.pdf")},
        content_type="multipart/form-data",
    )
    assert resp_upload.status_code == 302

    # Hantera inkommande kopplingsförfrågningar.
    monkeypatch.setattr(app.functions, "user_accept_link_request", lambda *_: True)
    resp_accept = client.post("/dashboard/kopplingsforfragan/test/godkann")
    assert resp_accept.status_code == 302

    monkeypatch.setattr(app.functions, "user_reject_link_request", lambda *_: False)
    resp_reject = client.post("/dashboard/kopplingsforfragan/test/avsla")
    assert resp_reject.status_code == 302

    monkeypatch.setattr(app.functions, "user_remove_supervisor_connection", lambda *_: True)
    resp_remove = client.post("/dashboard/kopplingar/test/ta-bort")
    assert resp_remove.status_code == 302

    monkeypatch.setattr(app.functions, "delete_user_pdf", lambda *_: True)
    resp_delete = client.post("/dashboard/intyg/1/ta-bort")
    assert resp_delete.status_code == 302


def test_user_upload_error_paths(monkeypatch, client):
    monkeypatch.setattr(app, "validate_csrf_token", lambda allow_if_absent=False: False)
    with client.session_transaction() as sess:
        _login_user(sess)
    resp_csrf = client.post("/dashboard/ladda-upp")
    assert resp_csrf.status_code == 302

    monkeypatch.setattr(app, "validate_csrf_token", lambda allow_if_absent=False: True)
    with client.session_transaction() as sess:
        _login_user(sess)
        sess.pop("personnummer_raw", None)
    resp_missing_pnr = client.post("/dashboard/ladda-upp")
    assert resp_missing_pnr.status_code == 302

    with client.session_transaction() as sess:
        _login_user(sess)
    resp_no_file = client.post("/dashboard/ladda-upp", data={"category": ""})
    assert resp_no_file.status_code == 302

    with client.session_transaction() as sess:
        _login_user(sess)
    resp_no_category = client.post(
        "/dashboard/ladda-upp",
        data={"category": "", "certificate": (io.BytesIO(b""), "")},
        content_type="multipart/form-data",
    )
    assert resp_no_category.status_code == 302

    def _raise_value_error(*_args, **_kwargs):
        raise ValueError("ogiltig")

    monkeypatch.setattr(app, "save_pdf_for_user", _raise_value_error)
    with client.session_transaction() as sess:
        _login_user(sess)
    resp_value_error = client.post(
        "/dashboard/ladda-upp",
        data={"category": "arbetsmiljo", "certificate": (io.BytesIO(b"x"), "fil.pdf")},
        content_type="multipart/form-data",
    )
    assert resp_value_error.status_code == 302

    def _raise_generic(*_args, **_kwargs):
        raise RuntimeError("fel")

    monkeypatch.setattr(app, "save_pdf_for_user", _raise_generic)
    with client.session_transaction() as sess:
        _login_user(sess)
    resp_generic_error = client.post(
        "/dashboard/ladda-upp",
        data={"category": "arbetsmiljo", "certificate": (io.BytesIO(b"x"), "fil.pdf")},
        content_type="multipart/form-data",
    )
    assert resp_generic_error.status_code == 302


def test_dashboard_actions_csrf_failures(monkeypatch, client):
    monkeypatch.setattr(app, "validate_csrf_token", lambda allow_if_absent=False: False)
    with client.session_transaction() as sess:
        _login_user(sess)

    resp_accept = client.post("/dashboard/kopplingsforfragan/x/godkann")
    resp_reject = client.post("/dashboard/kopplingsforfragan/x/avsla")
    resp_remove = client.post("/dashboard/kopplingar/x/ta-bort")
    resp_delete = client.post("/dashboard/intyg/2/ta-bort")

    assert all(r.status_code == 302 for r in (resp_accept, resp_reject, resp_remove, resp_delete))

