<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Deployment

En enkel guide för Docker-drift.

## Lokal utveckling med Docker

```bash
docker compose up --build
```

Vanliga adresser:
- App: `http://localhost:8080`
- Demo: `http://localhost:8081`
- Status: `http://localhost:8082`

## Produktion

```bash
cp .example.env .env
docker compose -f docker-compose.prod.yml up -d --build
```

Produktion använder bland annat:
- Traefik
- App
- Demoapp
- Statusservice
- PostgreSQL
- Backup-service
- (valfritt) antivirus via security-profil

## Automatisk molnbackup till OneDrive eller Dropbox

Den inbyggda tjänsten `postgres_backup` skapar komprimerade databasbackuper i Docker-volymen `pgdata_backups`. Om du vill spara samma backup automatiskt till OneDrive eller Dropbox kan du aktivera den valfria Compose-profilen `backup-cloud`, som använder `rclone`. OneDrive- eller Dropbox-programmet behöver inte vara installerat på servern.

### Steg

1. Fyll i `.env` med OAuth-uppgifterna for den remote du vill anvanda.
2. Satt foljande i `.env`:

```env
RCLONE_REMOTE=onedrive
RCLONE_BACKUP_PATH=jk-utbildnings-intyg/postgres
RCLONE_SYNC_INTERVAL_SECONDS=3600
RCLONE_PRUNE_REMOTE=false
RCLONE_ONEDRIVE_TOKEN='{"access_token":"...","token_type":"Bearer","refresh_token":"...","expiry":"2026-01-01T00:00:00Z"}'
RCLONE_ONEDRIVE_DRIVE_ID=din-drive-id
RCLONE_ONEDRIVE_DRIVE_TYPE=personal
```

3. Starta tjansten:

```bash
docker compose --profile backup-cloud up -d backup_cloud_sync
```

Det gar ocksa att anvanda `RCLONE_REMOTE=dropbox` och i stallet fylla i `RCLONE_DROPBOX_TOKEN` i `.env`.

### Hur det fungerar

- `postgres_backup` fortsatter att skapa `backup-*.sql.gz` lokalt.
- `backup_cloud_sync` genererar en intern `rclone.conf` fran `.env` med remotes for bade `onedrive` och `dropbox`.
- `backup_cloud_sync` kopierar filerna till `${RCLONE_REMOTE}:${RCLONE_BACKUP_PATH}`.
- Om `RCLONE_PRUNE_REMOTE=true` rensas fjarrbackuper som ar aldre an `BACKUP_RETENTION_DAYS`.

Observera: OneDrive och Dropbox anvander OAuth. Det betyder att du normalt sparar token/klientuppgifter i `.env`, inte ditt vanliga Microsoft- eller Dropbox-losenord.

Det har upplagget gor att du fortfarande har en lokal backup aven om molnleverantoren tillfalligt inte gar att na.

## PostgreSQL publik exponering

I produktion är PostgreSQL som standard endast bunden lokalt via `127.0.0.1`.

För att exponera PostgreSQL publikt, sätt i `.env`:

- `POSTGRES_BIND_IP=0.0.0.0`
- (valfritt) `POSTGRES_PUBLIC_PORT` för att byta extern port (default `1543`)

Varning: detta exponerar databasen mot internet. Begränsa alltid åtkomst med brandvägg och/eller IP-allowlist.

## Viktiga volymer

- `env_data`
- `app_logs`
- `traefik_logs`
- `pgdata`
- `pgdata_backups`

## Hjälpskript

Starta lokal app + postgres:

```bash
./scripts/start_postgres_stack.sh
```

## Cloudflare

För Cloudflare-guide, se:
[PUBLIC_DEPLOYMENT_CLOUDFLARE.md](PUBLIC_DEPLOYMENT_CLOUDFLARE.md)

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
