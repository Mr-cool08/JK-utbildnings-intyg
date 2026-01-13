# Critical Events Email Notifications

## Overview

The application now sends automatic email notifications to an admin email address for critical events such as application startup, shutdown, crashes, errors, and exceptions.

## Configuration

### Environment Variables

Add these variables to your `.env` or `.env` file:

```env
# Admin emails for critical events notifications (comma-separated for multiple)
ADMIN_EMAIL=admin@example.com
# Or for multiple recipients:
# ADMIN_EMAIL=admin1@example.com,admin2@example.com,admin3@example.com

# Application name (displayed in emails)
APP_NAME=JK Utbildningsintyg
```

**Required:**
- `ADMIN_EMAIL`: Email address(es) to which critical event notifications will be sent. Supports single or multiple addresses separated by commas.
- Existing SMTP configuration (`smtp_server`, `smtp_user`, `smtp_password`, `smtp_port`)

**Optional:**
- `APP_NAME`: Application name for display in emails (defaults to "JK Utbildningsintyg")

## Events That Trigger Notifications

### 1. **Application Startup** 🟢
Sent when the application starts successfully.
- **Includes:** Hostname, timestamp
- **Type:** Green notification

### 2. **Application Shutdown** 🟡
Sent when the application is shutting down gracefully.
- **Includes:** Shutdown reason, timestamp
- **Type:** Amber notification

### 3. **Application Crash** 🔴
Sent when an unhandled exception causes the application to crash.
- **Includes:** Error message, full traceback, timestamp
- **Type:** Red notification (critical)

### 4. **Critical HTTP Errors (500)** 🔴
Sent when a 500 Internal Server Error occurs.
- **Includes:** Endpoint, HTTP method, user IP address, error details
- **Type:** Red notification (critical)

### 5. **Unhandled Exceptions** ⚠️
Sent when an unhandled exception is caught.
- **Includes:** Exception type, message, context, full traceback
- **Type:** Red-orange notification

### 6. **Application Restart** 🔄
Can be manually triggered via API when needed.
- **Includes:** Restart reason, timestamp
- **Type:** Cyan notification

## Email Format

All notification emails include:

- **Color-coded header** based on severity
- **Event type** and timestamp
- **Application name** and hostname
- **Detailed description** of what occurred
- **Error message** (if applicable) with traceback
- **Action recommendations** for admins

## Implementation Details

### Key Files

1. **`services/critical_events.py`** - Core notification service
   - Email formatting and sending logic
   - Thread-safe async email delivery
   - HTML escaping for security
   - Environment variable management

2. **`app.py`** - Integration points
   - Startup notification via `@app.before_request`
   - Error handlers with email notifications
   - Shutdown notification via `@app.teardown_appcontext`

3. **`.env`** - Configuration
   - ADMIN_EMAIL and APP_NAME settings

### Design Considerations

- **Asynchronous delivery**: Emails are sent in background threads to avoid blocking the application
- **Security**: All user-provided content is HTML-escaped to prevent injection attacks
- **Error handling**: If email sending fails, the error is logged but doesn't interrupt the application
- **Thread-safe**: Safe to call from multiple concurrent requests
- **Graceful degradation**: Missing ADMIN_EMAIL will raise a RuntimeError to alert about misconfiguration

## API Reference

### Main Functions

```python
from services import critical_events

# Send startup notification
critical_events.send_startup_notification(hostname="server.example.com")

# Send shutdown notification
critical_events.send_shutdown_notification(reason="Maintenance scheduled")

# Send crash notification
critical_events.send_crash_notification(
    error_message="Database connection failed",
    traceback="..."
)

# Send critical HTTP error notification
critical_events.send_critical_error_notification(
    error_message="Unexpected error in request handler",
    endpoint="/api/users",
    user_ip="192.168.1.1"
)

# Send unhandled exception notification
critical_events.send_unhandled_exception_notification(
    error_message="AttributeError: 'NoneType' has no attribute 'id'",
    traceback="...",
    context="Processing user registration"
)

# Generic critical event notification
critical_events.send_critical_event_email(
    event_type="restart",
    title="Custom Event Title",
    description="What happened",
    error_message="Optional error details"
)
```

## Testing

Run the critical events test suite:

```bash
python -m pytest tests/test_critical_events.py -v
```

### Test Coverage

- Environment variable loading
- Email address validation
- Notification sending (mocked)
- HTML escaping for security
- Integration with Flask app

## Troubleshooting

### Emails not being sent

1. **Check ADMIN_EMAIL is set:**
   ```bash
   echo $ADMIN_EMAIL  # Should output: admin@example.com
   ```

2. **Verify SMTP configuration:**
   ```bash
   # Check these are set:
   - smtp_server
   - smtp_user
   - smtp_password
   - smtp_port
   ```

3. **Check application logs:**
   ```
   ERROR: Kan inte skicka kritisk event-email: <error details>
   ```

### ADMIN_EMAIL not configured error

If you see:
```
RuntimeError: ADMIN_EMAIL environment variable is not set
```

Add to your `.env`:
```env
ADMIN_EMAIL=admin@example.com
```

## Future Enhancements

Potential improvements:
- [ ] Database logging of sent notifications
- [ ] Notification history dashboard
- [ ] Notification level filtering (critical only, all events, etc.)
- [ ] Scheduled digest emails
- [ ] Webhook notifications as alternative to email
- [ ] SMS alerts for critical events
- [ ] Email template customization

## Security Notes

- All email content is HTML-escaped to prevent XSS attacks
- Error messages are sanitized before display
- PII (personally identifiable information) is never included in notifications
- SMTP credentials are loaded from secure environment variables
- Email sending happens asynchronously to prevent timing attacks

## Author Notes

Last updated: 2025-12-31
Configured for: admin@example.com
