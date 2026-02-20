# Copyright (c) Liam Suorsa
import logging


def test_email_error_handler_sends_emails_with_attachments(monkeypatch, tmp_path):
    # Prepare a small log file and attach a FileHandler to the root logger
    log_file = tmp_path / "test.log"
    sample_bytes = b"First line\nSecond line\n"
    log_file.write_bytes(sample_bytes)
    secondary_log_file = tmp_path / "secondary.log"
    secondary_bytes = b"Secondary log line\n"
    secondary_log_file.write_bytes(secondary_bytes)

    root = logging.getLogger()
    file_handler = logging.FileHandler(str(log_file))
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(file_handler)
    secondary_logger = logging.getLogger("secondary")
    secondary_handler = logging.FileHandler(str(secondary_log_file))
    secondary_handler.setFormatter(logging.Formatter("%(message)s"))
    secondary_logger.addHandler(secondary_handler)

    # Capture send_email calls
    calls = []

    def fake_send_email(recipient, subject, body, attachments=None):
        calls.append((recipient, subject, body, attachments))

    # Replace Thread with a synchronous runner so the test can observe calls
    class SyncThread:
        def __init__(self, target=None, args=(), daemon=None):
            self._target = target
            self._args = args

        def start(self):
            if self._target:
                self._target(*self._args)

    monkeypatch.setenv("ADMIN_EMAIL", "one@example.com,two@example.com")
    monkeypatch.setenv("HOSTNAME", "test-host")
    monkeypatch.setenv("APP_NAME", "utbildningsintyg.se")
    monkeypatch.setattr("functions.notifications.critical_events.Thread", SyncThread)
    monkeypatch.setattr("functions.emails.service.send_email", fake_send_email)

    # Attach the EmailErrorHandler from the module under test
    from functions.notifications import critical_events as ce

    handler = ce.EmailErrorHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s:%(message)s"))
    root.addHandler(handler)

    # Emit an ERROR record — should trigger two email sends (one per recipient)
    test_logger = logging.getLogger("tests.email_error")
    test_logger.error("This is a test error for email handler")

    assert len(calls) == 2
    recipients = {c[0] for c in calls}
    assert recipients == {"one@example.com", "two@example.com"}

    # Ensure attachments were provided and contain our sample content
    for _, subject, body, attachments in calls:
        assert subject and "Applikationsfel" in subject or "[FEL]" in subject
        assert "test-host" in body
        assert "utbildningsintyg.se" in body
        assert attachments is not None
        # attachments is a sequence of (filename, bytes)
        assert any(sample_bytes.splitlines()[0] in content for (_fn, content) in attachments)
        assert any(secondary_bytes.splitlines()[0] in content for (_fn, content) in attachments)

    # Clear captured calls and ensure CRITICAL does NOT trigger the handler
    calls.clear()
    test_logger.critical("This is critical and should not be handled by EmailErrorHandler")
    assert calls == []

    # Cleanup handlers we added
    root.removeHandler(file_handler)
    secondary_logger.removeHandler(secondary_handler)
    root.removeHandler(handler)
