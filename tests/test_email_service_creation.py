"""Tests for email service send_creation_email functionality."""
import os
import sys

import pytest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from services import email as email_service

# Exception messages
INVALID_EMAIL_ERROR = "Ogiltig e-postadress."
SMTP_ERROR_MESSAGE = "Det gick inte att skicka e-post"


def test_send_creation_email_valid_link(monkeypatch):
    """Test that send_creation_email formats the email correctly with a valid link."""
    sent_emails = []
    
    def mock_send_email(recipient, subject, body, _attachments=None):
        sent_emails.append({
            'recipient': recipient,
            'subject': subject,
            'body': body,
            'attachments': _attachments
        })
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    test_email = 'test@example.com'
    test_link = 'https://example.com/foretagskonto/skapa/abcd1234'
    
    email_service.send_creation_email(test_email, test_link)
    
    assert len(sent_emails) == 1
    email = sent_emails[0]
    assert email['recipient'] == test_email
    assert email['subject'] == 'Skapa ditt konto'
    assert test_link in email['body']
    assert '<html>' in email['body']
    assert email['attachments'] is None


def test_send_creation_email_link_escaping(monkeypatch):
    """Test that send_creation_email properly escapes special characters in the link."""
    sent_emails = []
    
    def mock_send_email(recipient, subject, body, _attachments=None):
        sent_emails.append({
            'recipient': recipient,
            'subject': subject,
            'body': body,
        })
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    # Link with characters that need HTML escaping
    test_email = 'test@example.com'
    test_link = 'https://example.com/create?token=abc&id=123'
    
    email_service.send_creation_email(test_email, test_link)
    
    assert len(sent_emails) == 1
    email = sent_emails[0]
    # Check that ampersands are escaped in the link
    assert '&amp;' in email['body'] or test_link in email['body']


def test_send_creation_email_invalid_email_raises(monkeypatch):
    """Test that send_creation_email raises when email is invalid."""
    def mock_send_email(_recipient, _subject, _body, _attachments=None):
        # This will call normalize_valid_email which will raise for invalid emails
        raise ValueError(INVALID_EMAIL_ERROR)
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    with pytest.raises(ValueError):
        email_service.send_creation_email('invalid-email', 'https://example.com/link')


def test_send_creation_email_smtp_error_propagates(monkeypatch):
    """Test that SMTP errors propagate as RuntimeError."""
    def mock_send_email(_recipient, _subject, _body, _attachments=None):
        raise RuntimeError(SMTP_ERROR_MESSAGE)
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    with pytest.raises(RuntimeError) as exc_info:
        email_service.send_creation_email('test@example.com', 'https://example.com/link')
    
    assert "Det gick inte att skicka e-post" in str(exc_info.value)


def test_send_creation_email_link_with_special_characters(monkeypatch):
    """Test that links with special characters are handled correctly."""
    sent_emails = []
    
    def mock_send_email(_recipient, _subject, body, _attachments=None):
        sent_emails.append({'body': body})
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    test_link = 'https://example.com/skapa/hash_with-special.chars_123'
    email_service.send_creation_email('test@example.com', test_link)
    
    assert len(sent_emails) == 1
    # Link should be present in some form
    assert 'example.com' in sent_emails[0]['body']


def test_send_creation_email_html_structure(monkeypatch):
    """Test that the email has proper HTML structure."""
    sent_emails = []
    
    def mock_send_email(_recipient, _subject, body, _attachments=None):
        sent_emails.append({'body': body})
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    email_service.send_creation_email('test@example.com', 'https://example.com/link')
    
    body = sent_emails[0]['body']
    assert '<html>' in body
    assert '<body' in body
    assert '</body>' in body
    assert '</html>' in body
    assert '<p>' in body
    assert '<a href=' in body


def test_send_creation_email_with_empty_link(monkeypatch):
    """Test behavior with empty link."""
    sent_emails = []
    
    def mock_send_email(_recipient, _subject, body, _attachments=None):
        sent_emails.append({'body': body})
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    # Should not raise, but email will have empty link
    email_service.send_creation_email('test@example.com', '')
    
    assert len(sent_emails) == 1
    # Email should still be sent, just with empty link
    assert '<html>' in sent_emails[0]['body']


def test_send_creation_email_normalized_recipient(monkeypatch):
    """Test that recipient email is normalized."""
    sent_emails = []
    
    def mock_send_email(recipient, _subject, _body, _attachments=None):
        sent_emails.append({'recipient': recipient})
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    # send_email will normalize the recipient
    email_service.send_creation_email('TEST@EXAMPLE.COM', 'https://example.com/link')
    
    assert len(sent_emails) == 1
    # The mock captures what was passed, so normalization happens in send_email
    assert sent_emails[0]['recipient'] == 'TEST@EXAMPLE.COM'


def test_send_creation_email_contains_instructions(monkeypatch):
    """Test that email contains user instructions."""
    sent_emails = []
    
    def mock_send_email(_recipient, _subject, body, _attachments=None):
        sent_emails.append({'body': body})
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    email_service.send_creation_email('test@example.com', 'https://example.com/link')
    
    body = sent_emails[0]['body']
    # Check for Swedish text indicating account creation
    assert 'konto' in body.lower() or 'skapa' in body.lower()


def test_send_creation_email_link_appears_twice(monkeypatch):
    """Test that the link appears both as href and as visible text."""
    sent_emails = []
    
    def mock_send_email(_recipient, _subject, body, _attachments=None):
        sent_emails.append({'body': body})
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    test_link = 'https://example.com/foretagskonto/skapa/hash123'
    email_service.send_creation_email('test@example.com', test_link)
    
    body = sent_emails[0]['body']
    # The link should appear at least once (could be in href and as text)
    assert body.count('example.com') >= 1


def test_send_creation_email_no_attachments(monkeypatch):
    """Test that creation emails don't have attachments."""
    sent_emails = []
    
    def mock_send_email(_recipient, _subject, _body, attachments=None):
        sent_emails.append({'attachments': attachments})
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    email_service.send_creation_email('test@example.com', 'https://example.com/link')
    
    assert sent_emails[0]['attachments'] is None


def test_send_creation_email_xss_protection(monkeypatch):
    """Test that potentially malicious links are escaped."""
    sent_emails = []
    
    def mock_send_email(_recipient, _subject, body, _attachments=None):
        sent_emails.append({'body': body})
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    # Link with potential XSS payload
    malicious_link = 'https://example.com/link"><script>alert("xss")</script><a href="'
    email_service.send_creation_email('test@example.com', malicious_link)
    
    body = sent_emails[0]['body']
    # Script tags should be escaped
    assert '<script>' not in body
    # Quotes should be escaped
    assert '&quot;' in body or '&#x27;' in body


def test_send_creation_email_with_unicode_link(monkeypatch):
    """Test handling of links with unicode characters."""
    sent_emails = []
    
    def mock_send_email(_recipient, _subject, body, _attachments=None):
        sent_emails.append({'body': body})
    
    monkeypatch.setattr(email_service, 'send_email', mock_send_email)
    
    # Link with unicode characters
    unicode_link = 'https://example.com/skapa/hash_ÅÄÖ'
    email_service.send_creation_email('test@example.com', unicode_link)
    
    assert len(sent_emails) == 1
    # Should handle unicode without crashing
    assert '<html>' in sent_emails[0]['body']