<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Utveckling

Snabbguide för lokal utveckling mot nuvarande projektstruktur.

## Lokal Python-körning

1. Skapa virtuell miljö:

```bash
python -m venv .venv
```

2. Aktivera miljön:

```powershell
.\.venv\Scripts\Activate.ps1
```

```bash
source .venv/bin/activate
```

3. Installera beroenden:

```bash
pip install -r requirements.txt
```

4. Kopiera `.example.env` till `.env`.

5. Sätt minst följande i `.env`:

```env
DEV_MODE=true
PORT=8080
```

6. Starta appen:

```bash
python app.py
```

Om du följer `.example.env` blir adressen normalt `http://localhost:8080`.

## DEV_MODE

`DEV_MODE` styr utvecklingsläget:

- `DEV_MODE=true` aktiverar utvecklingsloggning och debug-vänligt beteende.
- `DEV_MODE=false` ska användas i produktion.

Exempel:

```env
DEV_MODE=true
```

## Docker-utveckling

Starta hela stacken:

```bash
docker compose up --build
```

Viktiga lokala adresser:

- Huvudapp: `http://localhost`
- VS Code i webbläsaren: `http://localhost:8083` när `DEV_MODE=true`

## VS Code-container i webbläsaren

När `DEV_MODE=true` och `COMPOSE_PROFILES=${DEV_MODE:-false}` används startas tjänsten `vscode`.

Lägg till i `.env`:

```env
DEV_MODE=true
COMPOSE_PROFILES=${DEV_MODE:-false}
VSCODE_PASSWORD=byt-till-ett-starkt-losenord
VSCODE_BIND_IP=127.0.0.1
```

## Vanliga kvalitetskommandon

Kör tester:

```bash
pytest -n auto
```

Fallback:

```bash
pytest
```

Typkontroll:

```bash
mypy app.py functions services
```

Säkerhetsskanning:

```bash
bandit -r . -f json -o bandit.json --exit-zero
```

## Struktur efter städningen

- `app.py` ska vara tunn och främst montera ihop appen.
- `web/` är platsen för Flask-specifik struktur som routes, bootstrap och felhantering.
- När du städar vidare: flytta hellre kod mellan `web/`-moduler än att bygga upp en ny monolit i `app.py`.

## Driftstöd i repo

Interaktiv eller styrd Compose-hantering:

```bash
python scripts/manage_compose.py --action <stop|pull|up|cycle|git-pull|pytest|prune-volumes|system-df>
```

Uppdateringsskript:

```bash
python scripts/update_app.py
```

Observera att `update_app.py` och `manage_compose.py` utgår från `docker-compose.yml`.
På Linux-servrar där `crontab` finns installerat lägger `update_app.py` också in cron-raden för `expiry_reminder` om den saknas.
Schemat styrs via `CERTIFICATE_EXPIRY_REMINDER_CRON_SCHEDULE` i projektets `.env`.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
