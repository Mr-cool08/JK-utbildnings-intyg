<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Deployment

Det här projektet använder i dagsläget **en gemensam `docker-compose.yml`** för både lokal körning och serverdrift.

## Förberedelser

1. Kopiera `.example.env` till `.env`.
2. Fyll i minst databas-, admin- och SMTP-inställningar.
3. Kontrollera att certifikatvägar och domänvärden stämmer för servern.

Viktiga variabler att gå igenom:

- `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`
- `ADMIN_EMAIL`
- `admin_username`, `admin_password`
- `SECRET_KEY`, `HASH_SALT`
- `ORIGIN_CERT_PATH`, `ORIGIN_KEY_PATH`
- `TRUSTED_PROXY_COUNT`
- `PUBLIC_NETWORK_NAME` om du återanvänder ett externt Docker-nätverk

## Starta stacken

```bash
docker compose -f docker-compose.yml up -d --build
```

## Aktiva tjänster i nuvarande Compose

- `app` - huvudappen för `utbildningsintyg.se`
- `traefik` - TLS-terminering och domänrouting
- `postgres` - databasen
- `postgres_backup` - återkommande databasbackup
- `fail2ban` - skyddar i första hand SSH på origin-servern
- `vscode` - valfri utvecklartjänst när `DEV_MODE=true`
- `expiry_reminder` - schemalagt jobb för utgångspåminnelser

## Utgångspåminnelser

Tjänsten `expiry_reminder` kör bara `python -m scripts.send_expiry_reminders` och avslutas direkt när jobbet är klart.

Schema och dublettskydd styrs via miljövariabler:

```env
CERTIFICATE_EXPIRY_REMINDER_CRON_SCHEDULE=0 7 1 * *
CERTIFICATE_EXPIRY_REMINDER_DUPLICATE_GUARD_MINUTES=60
```

`update_app.py` läser `CERTIFICATE_EXPIRY_REMINDER_CRON_SCHEDULE` från projektets `.env` när cron-raden skapas på Linux-servrar.

Kör manuellt:

```bash
docker compose -f docker-compose.yml run --rm expiry_reminder
```

Exempel på cron den första dagen varje månad klockan 07:00:

```bash
0 7 1 * * cd /path/till/projekt && docker compose -f docker-compose.yml run --rm expiry_reminder
```

## Portar och exponering

Direkta host-portar i Compose:

- `80:80` - huvudappen
- `443:443` - Traefik för HTTPS
- `${POSTGRES_BIND_IP:-127.0.0.1}:${POSTGRES_PUBLIC_PORT:-1543}:5432` - PostgreSQL
- `${VSCODE_BIND_IP:-127.0.0.1}:8083:8080` - code-server vid DEV_MODE

För publik drift bör direktåtkomst till origin begränsas med brandvägg, särskilt om Cloudflare används framför servern.

## Fail2ban

`fail2ban` är konfigurerad för att läsa hostens SSH-loggar från `/var/log/auth.log` eller `/var/log/secure` och bannlysa upprepade inloggningsförsök mot SSH.

Publik webbtrafik bör i stället filtreras av Cloudflare och serverns brandvägg, så att fail2ban inte behöver vara primärt webbskydd för HTTP/HTTPS.

## Traefik och domäner

Traefik är konfigurerad för att routa minst följande domäner:

- `utbildningsintyg.se`
- `www.utbildningsintyg.se`
- `mta-sts.utbildningsintyg.se` för `/.well-known/mta-sts.txt`

## PostgreSQL publik exponering

Databasen är som standard endast bunden till loopback:

```env
POSTGRES_BIND_IP=127.0.0.1
POSTGRES_PUBLIC_PORT=1543
```

Om du måste exponera PostgreSQL utanför servern:

```env
POSTGRES_BIND_IP=0.0.0.0
```

Gör det bara tillsammans med brandvägg eller IP-allowlist.

## Backup

Lokal återkommande backup sköts av `postgres_backup`.

Tidigare dokumentation för separat molnsynk är legacy och gäller inte längre för nuvarande `docker-compose.yml`.
Om molnsynk behövs måste den sättas upp utanför den här Compose-konfigurationen.

## Hälsokontroll och aviseringar

Applikationen exponerar fortsatt `GET /health` för extern monitorering.

Inbyggd serverövervakning, interna smoke-tester och nattlig antivirusskanning ingår inte längre i Compose-stacken.
Kritiska appnotifieringar använder `ADMIN_EMAIL` via applikationens ordinarie notifieringsflöde.

## Hjälpskript

Compose-hantering:

```bash
python scripts/manage_compose.py --action <stop|pull|up|cycle|git-pull|pytest|prune-volumes|system-df>
```

Uppdateringssekvens:

```bash
python scripts/update_app.py
```

På Linux-servrar där `crontab` finns installerat säkerställer skriptet också att månadsjobbet för `expiry_reminder` finns inlagt en gång, utan dubbletter.

## Vid publik Cloudflare-drift

Se även:

- [PUBLIC_DEPLOYMENT_CLOUDFLARE.md](PUBLIC_DEPLOYMENT_CLOUDFLARE.md)
- [../deploy/mta-sts/README.md](../deploy/mta-sts/README.md)

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
