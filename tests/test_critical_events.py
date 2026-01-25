# Copyright (c) Liam Suorsa
# Test for critical events email notifications

import pytest
import os
from unittest.mock import patch, MagicMock
from functions.notifications import critical_events


class TestCriticalEventsNotifications:
    """Test suite for critical events email notifications."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        # Set up the required environment variables
        monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com")
        monkeypatch.setenv("APP_NAME", "JK Utbildningsintyg")
        monkeypatch.setenv("HOSTNAME", "test-host")

    def test_get_admin_email(self):
        """Test that admin email is retrieved correctly."""
        emails = critical_events._get_admin_emails()
        assert emails == ["admin@example.com"]

    def test_get_admin_emails_multiple(self, monkeypatch):
        """Test that multiple admin emails are retrieved correctly."""
        monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com,admin2@example.com,admin3@example.com")
        emails = critical_events._get_admin_emails()
        assert emails == ["admin@example.com", "admin2@example.com", "admin3@example.com"]

    def test_get_admin_emails_with_whitespace(self, monkeypatch):
        """Test that email addresses with surrounding whitespace are stripped."""
        monkeypatch.setenv("ADMIN_EMAIL", "  admin@example.com  ,  admin2@example.com  ")
        emails = critical_events._get_admin_emails()
        assert emails == ["admin@example.com", "admin2@example.com"]

    def test_get_admin_email_missing(self, monkeypatch):
        """Test that error is raised when ADMIN_EMAIL is not set."""
        monkeypatch.delenv("ADMIN_EMAIL", raising=False)
        with pytest.raises(RuntimeError):
            critical_events._get_admin_emails()

    def test_get_admin_email_empty(self, monkeypatch):
        """Test that error is raised when ADMIN_EMAIL is empty."""
        monkeypatch.setenv("ADMIN_EMAIL", "")
        with pytest.raises(RuntimeError):
            critical_events._get_admin_emails()

    def test_get_app_name(self):
        """Test that app name is retrieved correctly."""
        name = critical_events._get_app_name()
        assert name == "JK Utbildningsintyg"

    def test_get_app_name_default(self, monkeypatch):
        """Test that default app name is used when not set."""
        monkeypatch.delenv("APP_NAME", raising=False)
        name = critical_events._get_app_name()
        assert name == "JK Utbildningsintyg"

    @patch('functions.notifications.critical_events.email_service.send_email')
    def test_send_startup_notification(self, mock_send_email):
        """Test startup notification is sent correctly."""
        critical_events.send_startup_notification(hostname="test-server")
        
        # Give thread time to complete
        import time
        time.sleep(0.1)
        
        # Verify email was sent
        assert mock_send_email.called
        call_args = mock_send_email.call_args
        assert "admin@example.com" in str(call_args)
        assert "startad" in str(call_args).lower()

    @patch('functions.notifications.critical_events.email_service.send_email')
    def test_send_startup_notification_multiple_recipients(self, mock_send_email, monkeypatch):
        """Test startup notification is sent to multiple recipients."""
        monkeypatch.setenv("ADMIN_EMAIL", "admin1@example.com,admin2@example.com")
        critical_events.send_startup_notification(hostname="test-server")
        
        import time
        time.sleep(0.1)
        
        # Verify email was sent to both recipients
        assert mock_send_email.call_count == 2
        calls = [str(call) for call in mock_send_email.call_args_list]
        assert any("admin1@example.com" in call for call in calls)
        assert any("admin2@example.com" in call for call in calls)

    @patch('functions.notifications.critical_events.email_service.send_email')
    def test_send_shutdown_notification(self, mock_send_email):
        """Test shutdown notification is sent correctly."""
        critical_events.send_shutdown_notification(reason="Maintenance")
        
        import time
        time.sleep(0.1)
        
        assert mock_send_email.called
        call_args = mock_send_email.call_args
        assert "admin@example.com" in str(call_args)

    @patch('functions.notifications.critical_events.email_service.send_email')
    def test_send_crash_notification(self, mock_send_email):
        """Test crash notification is sent correctly."""
        critical_events.send_crash_notification(
            error_message="Database connection failed",
            traceback="Traceback (most recent call last)..."
        )
        
        import time
        time.sleep(0.1)
        
        assert mock_send_email.called
        call_args = mock_send_email.call_args
        assert "admin@example.com" in str(call_args)
        assert "kraschat" in str(call_args).lower()

    @patch('functions.notifications.critical_events.email_service.send_email')
    def test_send_critical_error_notification(self, mock_send_email):
        """Test critical error notification is sent correctly."""
        critical_events.send_critical_error_notification(
            error_message="Internal server error",
            endpoint="/api/test",
            user_ip="192.168.1.1"
        )
        
        import time
        time.sleep(0.1)
        
        assert mock_send_email.called
        call_args = mock_send_email.call_args
        assert "admin@example.com" in str(call_args)

    def test_send_critical_event_email_with_error_message(self):
        """Test that critical event email includes error message."""
        with patch('functions.notifications.critical_events.email_service.send_email') as mock_send:
            critical_events.send_critical_event_email(
                event_type="error",
                title="Test Error",
                description="Something went wrong",
                error_message="Detailed error: Connection timeout"
            )
            
            import time
            time.sleep(0.1)
            
            # Verify email formatting
            if mock_send.called:
                call_args = mock_send.call_args
                html_body = str(call_args)
                # Should contain error message
                assert "error" in html_body.lower() or "Connection timeout" in str(call_args)
                assert "test-host" in html_body

    def test_html_escaping_in_error_message(self):
        """Test that HTML is properly escaped in error messages."""
        with patch('functions.notifications.critical_events.email_service.send_email') as mock_send:
            critical_events.send_critical_event_email(
                event_type="error",
                title="Test Error",
                description="Normal description",
                error_message="<script>alert('xss')</script>"
            )
            
            import time
            time.sleep(0.1)
            
            # Verify that dangerous HTML was escaped
            if mock_send.called:
                call_args = str(mock_send.call_args)
                # Should not contain unescaped script tags
                assert "<script>" not in call_args or "&lt;script&gt;" in call_args

    @patch('functions.notifications.critical_events.email_service.send_email')
    def test_send_unhandled_exception_notification(self, mock_send_email):
        """Test unhandled exception notification."""
        critical_events.send_unhandled_exception_notification(
            error_message="AttributeError: 'NoneType' object has no attribute 'name'",
            traceback="Traceback...",
            context="Processing user upload"
        )
        
        import time
        time.sleep(0.1)
        
        assert mock_send_email.called


class TestEmailServiceCriticalAlerts:
    """Test suite for send_critical_event_alert function."""

    @patch('functions.emails.service.send_email')
    def test_send_critical_event_alert_single_email(self, mock_send_email, monkeypatch):
        """Test critical event alert is sent to a single email address."""
        from functions.emails import service as email
        monkeypatch.setenv("CRITICAL_ALERTS_EMAIL", "admin@example.com")
        
        email.send_critical_event_alert("startup", "Test details")
        
        # Verify email was sent
        assert mock_send_email.called
        call_args = mock_send_email.call_args
        assert "admin@example.com" in str(call_args)

    @patch('functions.emails.service.send_email')
    def test_send_critical_event_alert_multiple_emails(self, mock_send_email, monkeypatch):
        """Test critical event alert is sent to multiple email addresses."""
        from functions.emails import service as email
        monkeypatch.setenv("CRITICAL_ALERTS_EMAIL", "admin1@example.com,admin2@example.com,admin3@example.com")
        
        email.send_critical_event_alert("crash", "Critical error details")
        
        # Verify email was sent to all recipients
        assert mock_send_email.call_count == 3
        calls = [str(call) for call in mock_send_email.call_args_list]
        assert any("admin1@example.com" in call for call in calls)
        assert any("admin2@example.com" in call for call in calls)
        assert any("admin3@example.com" in call for call in calls)

    @patch('functions.emails.service.send_email')
    def test_send_critical_event_alert_with_whitespace(self, mock_send_email, monkeypatch):
        """Test critical event alert handles email addresses with whitespace."""
        from functions.emails import service as email
        monkeypatch.setenv("CRITICAL_ALERTS_EMAIL", "  admin1@example.com  ,  admin2@example.com  ")
        
        email.send_critical_event_alert("error", "Error details")
        
        # Verify email was sent to both recipients despite whitespace
        assert mock_send_email.call_count == 2
        calls = [str(call) for call in mock_send_email.call_args_list]
        assert any("admin1@example.com" in call for call in calls)
        assert any("admin2@example.com" in call for call in calls)

    @patch('functions.emails.service.send_email')
    def test_send_critical_event_alert_empty_email(self, mock_send_email, monkeypatch):
        """Test critical event alert handles empty email gracefully."""
        from functions.emails import service as email
        monkeypatch.setenv("CRITICAL_ALERTS_EMAIL", "")
        
        # Should not raise an exception, just return early
        email.send_critical_event_alert("startup", "Details")
        
        # Verify no email was sent
        assert not mock_send_email.called


class TestCriticalEventIntegration:
    """Integration tests with the Flask app."""

    @pytest.fixture
    def client(self):
        """Create Flask app test client."""
        from app import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_health_endpoint_works(self, client):
        """Test that health endpoint still works after critical events integration."""
        response = client.get('/health')
        assert response.status_code == 200
        assert response.json == {"status": "ok"}
