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
