<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Kritiska händelser och aviseringar

Projektet har två huvudsakliga spår för e-postbaserade aviseringar: applikationshändelser och serverövervakning.

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

## 2. Serverövervakning

`services/server_monitor/monitor.py` sköter driftaviseringar för bland annat:

- hög diskförbrukning
- hög RAM-användning
- hög CPU-användning
- smoke-tester mot definierade URL:er
- veckorapport för smoke-tester
- nattlig ClamAV-rapport

Viktiga variabler:

```env
CRITICAL_ALERTS_EMAIL=admin@example.com
SMTP_SERVER=smtp.example.se
SMTP_PORT=587
SMTP_USER=anvandare@example.se
SMTP_PASSWORD=hemligt
SMTP_TIMEOUT=30
MONITOR_CHECK_INTERVAL_SECONDS=60
MONITOR_SMOKE_TEST_TARGETS=Huvudsidan=https://utbildningsintyg.se/health
```

Övervakaren stöder även äldre lowercase-varianter som fallback för SMTP-inställningar.

## 3. E-posttjänster

Kod som används för att bygga och skicka meddelanden finns främst här:

- `functions/emails/service.py`
- `functions/notifications/critical_events.py`
- `services/server_monitor/monitor.py`

## 4. Vad som är bra att kontrollera i drift

- Att `ADMIN_EMAIL` är satt.
- Att SMTP fungerar både för appen och övervakaren.
- Att `CRITICAL_ALERTS_EMAIL` är satt om serverövervakningen ska skicka larm.
- Att smoke-tester pekar på stabila URL:er.

## 5. Relevanta tester

- `pytest tests/test_critical_events.py`
- `pytest tests/test_error_notifications.py`
- `pytest tests/test_email_env.py`
- `pytest tests/test_server_monitor_smoke.py`
- `pytest tests/test_server_monitor_config.py`

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
