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

## Demo-läge

`DEV_MODE` och `ENABLE_DEMO_MODE` är separata:

- `DEV_MODE=true` aktiverar utvecklingsloggning och debug-vänligt beteende.
- `ENABLE_DEMO_MODE=true` fyller applikationen med demodata.

Exempel:

```env
DEV_MODE=true
ENABLE_DEMO_MODE=true
```

## Docker-utveckling

Starta hela stacken:

```bash
docker compose up --build
```

Viktiga lokala adresser:

- Huvudapp: `http://localhost`
- Demo: `http://localhost:8000`
- Statussida: `http://localhost:8080`
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
mypy app.py functions services status_service
```

Säkerhetsskanning:

```bash
bandit -r . -f json -o bandit.json --exit-zero
```

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

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
