# Copyright (c) Liam Suorsa
import pytest

from functions.emails import service as email_service


def test_send_creation_email_uses_env_credentials(monkeypatch):
    """Säkerställ att send_creation_email använder uppgifterna från .env och skickar korrekt EmailMessage via STARTTLS."""
    from dotenv import dotenv_values

    # Läs in exempel-credentials
    env_values = dotenv_values(".example.env")
    for key in ("smtp_server", "smtp_port", "smtp_user", "smtp_password", "smtp_timeout"):
        monkeypatch.setenv(key, env_values[key])

    sent = {}

    class DummySMTP:
        def __init__(self, server, port, timeout=30):
            sent["server"] = server
            sent["port"] = port
            sent["timeout"] = timeout
            sent["ehlo_calls"] = 0
            sent["starttls_called"] = False

        def ehlo(self):
            sent["ehlo_calls"] += 1

        def starttls(self, context=None):
            # STARTTLS ska anropas på port 587
            sent["starttls_called"] = True
            sent["tls_context_provided"] = context is not None

        def login(self, user, password):
            sent["login"] = (user, password)

        def send_message(self, msg):
            # Spara hela EmailMessage för assertioner
            sent["message"] = msg

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

    # Peta in vår dummy i e-postmodulen
    monkeypatch.setattr(email_service, "SMTP", DummySMTP)

    # Kör funktionen
    link = "https://example.com/create"
    email_service.send_creation_email("liamsuorsa08@gmail.com", link)

    # Assertions: inloggning via env
    assert sent["login"] == (env_values["smtp_user"], env_values["smtp_password"])
    # Rätt server/port
    assert sent["server"] == env_values["smtp_server"]
    assert sent["port"] == int(env_values["smtp_port"])
    assert sent["timeout"] == int(env_values["smtp_timeout"])
    # STARTTLS-sekvensen kördes
    assert sent["starttls_called"] is True
    assert sent["ehlo_calls"] >= 2  # EHLO före och efter STARTTLS
    assert sent["tls_context_provided"] is True

    # Meddelandet skickades med korrekta headers och innehåll
    msg = sent["message"]
    assert msg["From"] == env_values["smtp_user"]
    assert msg["To"] == "liamsuorsa08@gmail.com"
    assert msg["Subject"] == "Skapa ditt konto"
    # Innehållet ska innehålla länken
    assert link in msg.get_content()


def test_send_creation_email_uses_ssl_on_port_465(monkeypatch):
    """Om port 465 anges ska funktionen använda SMTP_SSL utan STARTTLS."""
    from dotenv import dotenv_values

    env_values = dotenv_values(".example.env")
    for key in ("smtp_server", "smtp_user", "smtp_password", "smtp_timeout"):
        monkeypatch.setenv(key, env_values[key])
    monkeypatch.setenv("smtp_port", "465")

    sent = {}

    class DummySMTPSSL:
        def __init__(self, server, port, context=None, timeout=30):
            sent["server"] = server
            sent["port"] = port
            sent["timeout"] = timeout
            sent["context_provided"] = context is not None

        def ehlo(self):
            sent["ehlo_called"] = True

        def login(self, user, password):
            sent["login"] = (user, password)

        def send_message(self, msg):
            sent["message"] = msg

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

    class FailSMTP:
        def __init__(self, *args, **kwargs):
            raise AssertionError("SMTP should not be used for port 465")

    monkeypatch.setattr(email_service, "SMTP_SSL", DummySMTPSSL)
    monkeypatch.setattr(email_service, "SMTP", FailSMTP)

    link = "https://example.com/create"
    email_service.send_creation_email("liamsuorsa08@gmail.com", link)

    assert sent["login"] == (env_values["smtp_user"], env_values["smtp_password"])
    assert sent["server"] == env_values["smtp_server"]
    assert sent["port"] == 465
    assert sent["timeout"] == int(env_values["smtp_timeout"])
    assert sent["context_provided"] is True
    msg = sent["message"]
    assert msg["From"] == env_values["smtp_user"]
    assert msg["To"] == "liamsuorsa08@gmail.com"
    assert msg["Subject"] == "Skapa ditt konto"
    assert link in msg.get_content()


def test_send_creation_email_raises_on_refused_recipient(monkeypatch):
    """Ett avvisat mottagarsvar från SMTP ska ge ett fel."""
    from dotenv import dotenv_values

    env_values = dotenv_values(".example.env")
    for key in ("smtp_server", "smtp_port", "smtp_user", "smtp_password"):
        monkeypatch.setenv(key, env_values[key])

    class RefusingSMTP:
        def __init__(self, server, port, timeout=30):
            pass

        def ehlo(self):
            pass

        def starttls(self, context=None):
            pass

        def login(self, user, password):
            pass

        def send_message(self, msg):
            return {msg["To"]: (550, b"Mailbox unavailable")}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

    monkeypatch.setattr(email_service, "SMTP", RefusingSMTP)

    with pytest.raises(RuntimeError) as exc:
        email_service.send_creation_email(
            "liamsuorsa08@gmail.com", "https://example.com/create"
        )

    assert "accepterade inte mottagaren" in str(exc.value)
