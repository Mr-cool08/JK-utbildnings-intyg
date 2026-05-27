<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/43a0995859d24aaf96f0397be4069dc4)](https://app.codacy.com/gh/Mr-cool08/JK-utbildnings-intyg/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/43a0995859d24aaf96f0397be4069dc4)](https://app.codacy.com/gh/Mr-cool08/JK-utbildnings-intyg/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)
![Uptime Robot ratio (30 days)](https://img.shields.io/uptimerobot/ratio/m802374823-3a8d4541c53b344b63c35538?label=Demo%20site%20uptime)
![Uptime Robot ratio (30 days)](https://img.shields.io/uptimerobot/ratio/m802374820-0fe3051da2a9b338bddefd42?label=Status%20site%20uptime)
![Uptime Robot ratio (30 days)](https://img.shields.io/uptimerobot/ratio/m802374649-19fecede0f8e395e27276d11?label=Utbildningsintyg.se%20uptime)
![Website](https://img.shields.io/website?url=https%3A%2F%2Futbildningsintyg.se&label=utbildningsintyg.se)
![GitHub top language](https://img.shields.io/github/languages/top/Mr-cool08/JK-utbildnings-intyg)

# JK Utbildningsintyg

JK Utbildningsintyg är en Flask-baserad tjänst för att hantera utbildningsintyg som PDF för både standardkonton och företagskonton.

## Aktuella huvudfunktioner

- Publika sidor för startsida, ansökan, pris och organisationssökning.
- Ansökningsflöden för både `standardkonto` och `företagskonto`.
- Adminpanel för ansökningar, konton, intyg, företagskopplingar, fakturering och avancerad tabelladministration.
- Användardashboard där användare kan se, dela och ladda upp intyg samt hantera kopplingar till företagskonton.
- Företagskonton med egen inloggning, kopplingsförfrågningar och delning av användares PDF:er.
- Statussida, serverövervakning, säkerhetsloggning och Docker-baserad drift.

## Snabbstart lokalt

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

4. Kopiera `.example.env` till `.env` och sätt minst:

```env
DEV_MODE=true
PORT=8080
```

5. Starta appen:

```bash
python app.py
```

Om du använder värdena från `.example.env` kör appen normalt på `http://localhost:8080`. Om `PORT` saknas används `8000`.

## DEV_MODE och demo

`DEV_MODE` är den enda officiella växeln för utvecklingsläge.

- `DEV_MODE=true` aktiverar lokal debug-loggning och utvecklarvänligt beteende.
- `DEV_MODE=false` ska användas i produktion.
- `ENABLE_DEMO_MODE=true` startar demodata och demon separat från vanligt dev-läge.

Exempel:

```env
DEV_MODE=true
ENABLE_DEMO_MODE=false
PORT=8080
```

## Docker

Projektet använder i dagsläget en gemensam `docker-compose.yml` för både lokal körning och serverdrift.

### Starta hela stacken

```bash
docker compose up --build
```

Viktiga host-portar i Compose:

- Huvudapp: `http://localhost`
- Demoapp: `http://localhost:8000`
- Statussida: `http://localhost:8080`
- VS Code i webbläsaren: `http://localhost:8083` när `DEV_MODE=true`
- PostgreSQL: `127.0.0.1:1543` som standard

### VS Code-container i DEV_MODE

När `DEV_MODE=true` och `COMPOSE_PROFILES=${DEV_MODE:-false}` används startas även `code-server`.

```env
DEV_MODE=true
COMPOSE_PROFILES=${DEV_MODE:-false}
VSCODE_PASSWORD=byt-till-ett-starkt-losenord
VSCODE_BIND_IP=127.0.0.1
```

Containern monterar hela projektet till `/workspace`. Sätt bara `VSCODE_BIND_IP=0.0.0.0` om åtkomsten skyddas på annat sätt.

### Molnbackup med rclone

`postgres_backup` skapar lokala `.sql.gz`-backuper. Om du även vill synka dem till OneDrive eller Dropbox kan du aktivera den valfria tjänsten `backup_cloud_sync`.

```env
RCLONE_REMOTE=onedrive
RCLONE_BACKUP_PATH=jk-utbildnings-intyg/postgres
RCLONE_SYNC_INTERVAL_SECONDS=3600
RCLONE_PRUNE_REMOTE=false
RCLONE_ONEDRIVE_TOKEN='{"access_token":"...","token_type":"Bearer","refresh_token":"...","expiry":"2026-01-01T00:00:00Z"}'
RCLONE_ONEDRIVE_DRIVE_ID=din-drive-id
RCLONE_ONEDRIVE_DRIVE_TYPE=personal
```

```bash
docker compose --profile backup-cloud up -d backup_cloud_sync
```

Tjänsten genererar själv sin `rclone.conf` från miljövariablerna i containern.

## Kvalitetskontroller

Kör helst tester parallellt:

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

## Drift och underhåll

Lokal appstart:

```bash
python app.py
```

Vanligt hjälpskript:

```bash
python scripts/manage_compose.py --action <stop|pull|up|cycle|git-pull|pytest|prune-volumes|system-df>
```

## Viktiga dokument

- Dokumentationsindex: [docs/INDEX.md](docs/INDEX.md)
- Utveckling: [docs/UTVECKLING.md](docs/UTVECKLING.md)
- Drift: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- Cloudflare: [docs/PUBLIC_DEPLOYMENT_CLOUDFLARE.md](docs/PUBLIC_DEPLOYMENT_CLOUDFLARE.md)
- Adminguide i appen: [admin.md](admin.md)
- Adminpanel för utvecklare: [docs/ADMIN_PANEL.md](docs/ADMIN_PANEL.md)
- Säkerhet: [docs/SECURITY.md](docs/SECURITY.md)
- Testinventering: [tests.md](tests.md)

## Kort systemflöde

1. En användare ansöker om standardkonto eller företagskonto.
2. Admin granskar ansökan och skickar aktiveringslänk.
3. Konto skapas och användaren eller företagskontot loggar in.
4. PDF-intyg laddas upp, visas, delas och kopplas vid behov till företag.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
