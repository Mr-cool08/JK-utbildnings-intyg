<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Kritiska händelser och e-post

Systemet kan skicka e-post när allvarliga saker händer.

## Exempel på händelser

- Appen startar
- Appen stängs ner
- Krasch eller obehandlat fel
- HTTP 500-fel

## Konfiguration i `.env`

```env
ADMIN_EMAIL=admin@example.com
APP_NAME=JK Utbildningsintyg
```

SMTP måste också vara ifyllt (`smtp_server`, `smtp_user`, `smtp_password`, med flera).

## Kodplats

Logiken finns i:
- `functions/notifications/critical_events.py`
- `functions/emails/service.py`

## Test

```bash
pytest tests/test_critical_events.py
```

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
