def test_send_creation_email_uses_env_credentials(monkeypatch):
    """Ensure send_creation_email uses login details from the .env file."""
    from dotenv import dotenv_values
    import app

    # Load credentials from the example .env file
    env_values = dotenv_values('.example.env')
    # Apply only SMTP-related settings to the environment
    for key in ('smtp_server', 'smtp_port', 'smtp_user', 'smtp_password'):
        monkeypatch.setenv(key, env_values[key])

    sent = {}

    class DummySMTP:
        def __init__(self, server, port):
            sent['server'] = server
            sent['port'] = port

        def starttls(self):
            pass

        def login(self, user, password):
            sent['login'] = (user, password)

        def sendmail(self, from_addr, to_addr, message):
            sent['mail'] = (from_addr, to_addr, message)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

    monkeypatch.setattr(app, 'SMTP', DummySMTP)

    link = 'https://example.com/create'
    app.send_creation_email('liam@suorsa.se', link)

    # Credentials from the .env file should be used for login
    assert sent['login'] == (env_values['smtp_user'], env_values['smtp_password'])
    # Email should be sent from the smtp_user to Liam with the provided link
    from_addr, to_addr, msg = sent['mail']
    assert from_addr == env_values['smtp_user']
    assert to_addr == 'liam@suorsa.se'
    assert link in msg
