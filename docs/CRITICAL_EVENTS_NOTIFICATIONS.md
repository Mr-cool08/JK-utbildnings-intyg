<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Kritiska händelser och e-postaviseringar

Applikationen skickar automatiska e-postaviseringar vid kritiska händelser, till exempel uppstart, nedstängning och 500-fel. Aviseringarna går till administratörer som anges i miljövariablerna.

## Konfiguration

Lägg till följande i `.env`:

```env
# Kritiska event-notifikationer (komma-separerade adresser stöds)
ADMIN_EMAIL=admin@example.com

# Valfritt namn som visas i e-postens rubrik
APP_NAME=JK Utbildningsintyg
```

SMTP-konfigurationen måste också vara korrekt ifylld (exempelvis `smtp_server`, `smtp_user`, `smtp_password`, `smtp_port`).

## Händelser som triggar aviseringar

- **Applikation startad** (startup)
- **Applikation stängs ner** (shutdown)
- **Applikationen kraschar** (crash)
- **Kritiskt HTTP-fel (500)** (error)
- **Obehandlad exception** (exception)
- **Manuell omstart** (restart)

## Innehåll i aviseringar

Varje e-post innehåller:

- Tidsstämpel
- Applikationsnamn
- Händelsetyp och beskrivning
- Eventuellt felmeddelande eller traceback
- Logg-bilagor (om loggar är tillgängliga)

## Tekniska detaljer

Funktionaliteten finns i `functions/notifications/critical_events.py` och använder `functions.emails.service` för utskick. Aviseringar skickas asynkront för att inte blockera applikationen.

## Testning

Kör den specifika testsviten:

```bash
pytest tests/test_critical_events.py
```

Kör hela testsviten:

```bash
pytest
```
