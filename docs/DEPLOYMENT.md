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

- `80:80` - Traefik, med omdirigering till HTTPS
- `443:443` - Traefik för HTTPS
- `${POSTGRES_BIND_IP:-127.0.0.1}:${POSTGRES_PUBLIC_PORT:-1543}:5432` - PostgreSQL
- `${VSCODE_BIND_IP:-127.0.0.1}:8083:8080` - code-server vid DEV_MODE

För publik drift bör direktåtkomst till origin begränsas med brandvägg, särskilt om Cloudflare används framför servern.

## Fail2ban

`fail2ban` läser värdens SSH-logg `/var/log/auth.log` och blockerar efter fem matchande fel inom tio minuter i en timme. Före start måste den lokala filen `deploy/fail2ban/ssh-access.local` skapas med administrationsadress och SSH-port. Följ [driftsättningsguiden för Fail2ban](../deploy/fail2ban/README.md) för förkontroll, säker aktivering och verifiering.

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

## HTTP på dev-servern utan port 443

Produktionsstarten ovan kräver Traefik, port 443 och origin-certifikat.
`app` har endast `expose: 80`, vilket inte publicerar någon port på värden.
För dev-servern finns tjänsten `dev_http` i samma `docker-compose.yml`.
Den är profilavstängd som standard och vägrar starta utan exakt `DEV_MODE=true`.
Den använder en separat HTTP-konfiguration utanför produktionsproxyns
konfigurationskatalog, utan certifikat, HTTPS-omdirigering eller Docker-socket.

Kör endast på dev-servern och från dess befintliga projektkatalog. Behåll
projektnamn, databasinställningar och volymer. Hämta först den granskade
kodändringen genom er vanliga Git-rutin. Kontrollera därefter nuläget:

```bash
git rev-parse --short HEAD
docker compose -f docker-compose.yml ps --all
docker compose -f docker-compose.yml port app 80
sudo ss -ltnp '( sport = :80 or sport = :443 )'
docker compose -f docker-compose.yml exec -T app curl -fsS http://127.0.0.1:80/health
```

För den första återställningen behövs ingen omstart eller ombyggnad av appen.
Följande stoppar endast projektets produktionsproxy på dev-servern och startar
HTTP-proxyn. Bindningen begränsas till serverns LAN-adress:

```bash
DEV_MODE=true DEV_HTTP_BIND_IP=192.168.10.116 docker compose -f docker-compose.yml --profile dev-http config --quiet
docker compose -f docker-compose.yml stop traefik
DEV_MODE=true DEV_HTTP_BIND_IP=192.168.10.116 docker compose -f docker-compose.yml up -d --no-deps dev_http
docker compose -f docker-compose.yml ps --all dev_http app
docker compose -f docker-compose.yml port dev_http 80
docker compose -f docker-compose.yml logs --tail=50 dev_http
curl --max-time 10 -i http://192.168.10.116/health
curl --max-time 10 -I http://192.168.10.116/
```

Förväntat: HTTP 200 på `/health`, en publicerad `192.168.10.116:80` och ingen
HTTPS-omdirigering från proxyn. Kör även curl från en annan dator på LAN.
Om det fungerar på servern men inte från LAN återstår nätverk/brandvägg att
undersöka. Kontrollera också inloggning och formulär i webbläsaren.
Tailscale på 443 och övriga tjänster behöver inte ändras.

För bestående dev-konfiguration, ändra endast följande i dev-serverns befintliga
`.env`, utan att ersätta filens databasvärden eller hemligheter:

```dotenv
DEV_MODE=true
DEV_HTTP_BIND_IP=192.168.10.116
```

`dev_server.env` läses inte automatiskt. `update_app.py` läser processmiljön,
sedan `/config/.env` om den finns på värden, sedan projektets `.env`, utan att
skriva över redan satta värden. Använd exakt `true`; standardläget är `false`.
Flaggan aktiverar även appens befintliga debugbeteende nästa gång appen återskapas.

`update_app.py` väljer nu `dev_http` i stället för `traefik` när `DEV_MODE=true`.
I övriga lägen väljs produktionsproxyn och `dev_http` utesluts. Skriptets vanliga
uppdateringsflöde stoppar dock fortfarande hela stacken, bygger om, hanterar
Fail2ban/cron och rensar Docker-data. Använd därför de riktade kommandona ovan
för just denna reparation. Ett allmänt `docker compose up -d` väljer fortfarande
produktionsstarten; aktivera inte båda proxyerna på samma värdport.

Återställning av denna dev-åtgärd: `docker compose -f docker-compose.yml stop dev_http`.
Det återgår till läget utan extern HTTP-åtkomst och ändrar inga volymer.
Vid ett avsiktligt byte till produktionsdrift måste dev-proxyn först stoppas;
produktionsdrift använder `DEV_MODE=false` och kräver fungerande port 443 och TLS.

## Vid publik Cloudflare-drift

Se även:

- [PUBLIC_DEPLOYMENT_CLOUDFLARE.md](PUBLIC_DEPLOYMENT_CLOUDFLARE.md)
- [../deploy/mta-sts/README.md](../deploy/mta-sts/README.md)

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
