<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/43a0995859d24aaf96f0397be4069dc4)](https://app.codacy.com/gh/Mr-cool08/JK-utbildnings-intyg/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/43a0995859d24aaf96f0397be4069dc4)](https://app.codacy.com/gh/Mr-cool08/JK-utbildnings-intyg/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)
![Uptime Robot ratio (30 days)](https://img.shields.io/uptimerobot/ratio/m802374823-3a8d4541c53b344b63c35538?label=Demo%20site%20uptime)
![Uptime Robot ratio (30 days)](https://img.shields.io/uptimerobot/ratio/m802374820-0fe3051da2a9b338bddefd42?label=Status%20site%20uptime)
![Uptime Robot ratio (30 days)](https://img.shields.io/uptimerobot/ratio/m802374649-19fecede0f8e395e27276d11?label=Utbildningsintyg.se%20uptime)
![Website](https://img.shields.io/website?url=https%3A%2F%2Futbildningsintyg.se&label=utbildningsintyg.se)
![GitHub top language](https://img.shields.io/github/languages/top/Mr-cool08/JK-utbildnings-intyg)


# JK Utbildningsintyg

Det här systemet hjälper skolor och företag att spara utbildningsintyg i PDF.

## Vad systemet gör

- Admin kan skapa konton.
- Admin kan ladda upp PDF-intyg.
- Användare kan logga in och hämta sina intyg.
- Företagskonton kan koppla flera användare.

## Snabbstart (lokalt)

1. Skapa virtuell miljö och installera paket:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Skapa miljöfil:

```bash
cp .example.env .env
```

3. Starta appen:

```bash
python app.py
```

Appen kör normalt på `http://localhost:8000`.

## DEV_MODE (utvecklingsläge)

`DEV_MODE` är huvudknappen för utvecklingsläge.

- Sätt `DEV_MODE=true` när du utvecklar lokalt.
- Sätt `DEV_MODE=false` i produktion.

Exempel i `.env`:

```env
DEV_MODE=true
PORT=8080
```

## Docker

### Lokal Docker-stack

```bash
docker compose up --build
```

Huvudtjänsterna publiceras direkt på värdportar:
- Huvudapp: `http://<server-ip>:80`
- Status: `http://<server-ip>:8080`
- Demo: `http://<server-ip>:8000`

Traefik fungerar parallellt som tidigare för domän/HTTPS-routing.

### Produktion

För produktion, se: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

### Automatisk molnbackup av databasen

Det går att skicka de befintliga PostgreSQL-backuperna vidare till OneDrive eller Dropbox via `rclone`. OneDrive- eller Dropbox-programmet behöver inte vara installerat på servern.

1. Lägg in OAuth-uppgifterna i `.env`. För `RCLONE_REMOTE=onedrive` används OneDrive-värdena, och för `RCLONE_REMOTE=dropbox` används Dropbox-värdena.
2. Sätt i `.env`:

```env
RCLONE_REMOTE=onedrive
RCLONE_BACKUP_PATH=jk-utbildnings-intyg/postgres
RCLONE_SYNC_INTERVAL_SECONDS=3600
RCLONE_PRUNE_REMOTE=false
RCLONE_ONEDRIVE_TOKEN='{"access_token":"...","token_type":"Bearer","refresh_token":"...","expiry":"2026-01-01T00:00:00Z"}'
RCLONE_ONEDRIVE_DRIVE_ID=din-drive-id
RCLONE_ONEDRIVE_DRIVE_TYPE=personal
```

3. Starta backup-synken:

```bash
docker compose --profile backup-cloud up -d backup_cloud_sync
```

Tjänsten genererar själv en `rclone.conf` i containern från `.env`, så du behöver ingen separat konfigurationsfil på servern. Den vanliga databackupen fortsätter att skriva `.sql.gz`-filer till den lokala backupvolymen, och `backup_cloud_sync` kopierar dem sedan vidare till vald molnlagring.

## Antivirus (valfritt)

Det finns en separat antivirus-tjänst i Docker-profiler.

Starta den så här:

```bash
docker compose --profile security up --build antivirus
```

Du kan lägga till egna undantag för skanning med `ANTIVIRUS_EXTRA_EXCLUDE_DIRS` i `.env`.
Format: kommaseparerad eller kolonseparerad lista.
Exempel: `ANTIVIRUS_EXTRA_EXCLUDE_DIRS=/host/tmp,/host/var/cache:/host/home/app/.cache`

## Viktiga dokument

- Dokumentationsindex: [docs/INDEX.md](docs/INDEX.md)
- Drift: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- Cloudflare: [docs/PUBLIC_DEPLOYMENT_CLOUDFLARE.md](docs/PUBLIC_DEPLOYMENT_CLOUDFLARE.md)
- Säkerhet: [docs/SECURITY.md](docs/SECURITY.md)

## Tester

Kör hela testsviten:

```bash
pytest -n auto
```

Om `-n auto` inte fungerar, kör:

```bash
pytest
```

## Kort flöde

1. En användare ansöker eller läggs till av admin.
2. Konto aktiveras.
3. PDF-intyg laddas upp.
4. Användaren loggar in och laddar ner intyg.

Se även: [ACCOUNT_REQUEST_TO_PDF_FLOW.md](ACCOUNT_REQUEST_TO_PDF_FLOW.md).

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
