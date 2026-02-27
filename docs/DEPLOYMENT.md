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
