def test_send_creation_email_uses_env_credentials(monkeypatch):
    """Säkerställ att send_creation_email använder uppgifterna från .env och skickar korrekt EmailMessage via STARTTLS."""
    from dotenv import dotenv_values
    import app

    # Läs in exempel-credentials
    env_values = dotenv_values(".example.env")
    for key in ("smtp_server", "smtp_port", "smtp_user", "smtp_password"):
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

    # Peta in vår dummy i app-modulen
    monkeypatch.setattr(app, "SMTP", DummySMTP)

    # Kör funktionen
    link = "https://example.com/create"
    app.send_creation_email("liamsuorsa08@gmail.com", link)

    # Assertions: inloggning via env
    assert sent["login"] == (env_values["smtp_user"], env_values["smtp_password"])
    # Rätt server/port
    assert sent["server"] == env_values["smtp_server"]
    assert sent["port"] == int(env_values["smtp_port"])
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
