<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Kritiska händelser och aviseringar

Projektet har ett huvudsakligt spår för e-postbaserade aviseringar: applikationens kritiska händelser.

## 1. Applikationens kritiska händelser

Applikationen använder `functions/notifications/critical_events.py` för att skicka notifieringar om:

- uppstart
- omstart
- krasch
- obehandlade undantag
- kritiska HTTP-fel
- ERROR-loggar via e-posthandler med cooldown

Primär mottagare styrs av:

```env
ADMIN_EMAIL=admin@example.com
```

Flera mottagare kan anges kommaseparerat.

## 2. E-posttjänster

Kod som används för att bygga och skicka meddelanden finns främst här:

- `functions/emails/service.py`
- `functions/notifications/critical_events.py`

## 3. Vad som är bra att kontrollera i drift

- Att `ADMIN_EMAIL` är satt.
- Att SMTP fungerar för appens notifieringar.
- Att extern monitorering använder `/health` om tillgänglighetskontroll behövs.

PDF-uppladdningar skannas fortfarande separat med Quicksand i uppladdningsflödet, men det är inte ett eget e-postbaserat aviseringsspår.

## 4. Relevanta tester

- `pytest tests/test_critical_events.py`
- `pytest tests/test_error_notifications.py`
- `pytest tests/test_email_env.py`

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
