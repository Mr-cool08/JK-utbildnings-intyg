<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Deployment

Det här projektet använder i dagsläget **en gemensam `docker-compose.yml`** för både lokal körning och serverdrift.

## Förberedelser

1. Vid nyinstallation, kopiera `.example.env` till `.env`. Vid migrering, behåll serverns befintliga `.env`.
2. Fyll i minst databas-, admin- och SMTP-inställningar.
3. Kontrollera att `docker network inspect jk_public_net` hittar det externa nätverket. På en separat dev-värd skapar administratören vid behov nätverket en gång med `docker network create jk_public_net`. För produktion, följ migreringsordningen nedan.

Viktiga variabler att gå igenom:

- `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`
- `ADMIN_EMAIL`
- `admin_username`, `admin_password`
- `SECRET_KEY`, `HASH_SALT`
- `TRUSTED_PROXY_COUNT`

## Starta stacken

```bash
docker compose -f docker-compose.yml up -d --build
```

## Aktiva tjänster i nuvarande Compose

- `app` - huvudappen för `utbildningsintyg.se`
- `dev_http` - valfri HTTP-proxy på separat dev-server
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

- `${POSTGRES_BIND_IP:-127.0.0.1}:${POSTGRES_PUBLIC_PORT:-1543}:5432` - PostgreSQL
- `${VSCODE_BIND_IP:-127.0.0.1}:8083:8080` - code-server vid DEV_MODE

För publik drift bör direktåtkomst till origin begränsas med brandvägg, särskilt om Cloudflare används framför servern.

## Fail2ban

`fail2ban` läser värdens SSH-logg `/var/log/auth.log` och blockerar efter fem matchande fel inom tio minuter i en timme. Före start måste den lokala filen `deploy/fail2ban/ssh-access.local` skapas med administrationsadress och SSH-port. Följ [driftsättningsguiden för Fail2ban](../deploy/fail2ban/README.md) för förkontroll, säker aktivering och verifiering.

Publik webbtrafik bör i stället filtreras av Cloudflare och serverns brandvägg, så att fail2ban inte behöver vara primärt webbskydd för HTTP/HTTPS.

## Extern Traefik: routing och TLS sköts centralt

**Det här applikationsprojektet äger inte produktionsroutrar, certifikat, TLS-inställningar eller proxy-middlewares.** De ligger i den separata proxystacken [Mr-cool08/traefik](https://github.com/Mr-cool08/traefik):

- `dynamic/utbildningsintyg.yml` definierar domänreglerna för `utbildningsintyg.se`, `www.utbildningsintyg.se` och MTA-STS, HTTPS på `websecure`, routrar, tjänst och middleware-kopplingar.
- `dynamic/tls.yml` definierar delade säkerhetsheaders, uppladdningsgränser och certifikat. Privata nycklar förvaras endast på servern.
- `docker-compose.yml` i **det här repot** ansluter `app` till det externa Docker-nätverket `jk_public_net` med alias `utbildningsintyg-web`, och exponerar bara containerns port 80. Databasen förblir på `db_net`.
- Den gemensamma Traefik-containern når appen via `http://utbildningsintyg-web:80` i Docker-nätverket; den publika anslutningen är HTTPS. Applikationens `PREFERRED_URL_SCHEME=https` och `SESSION_COOKIE_SECURE=true` måste behållas. Sätt `TRUSTED_PROXY_COUNT` enligt den verkliga kedjan av betrodda proxysteg.

Att låta appen sakna Traefik-labels är avsiktligt. Docker-providern har `exposedByDefault=false`, så **utan den centrala routingfilen blir appen inte publik**.

### Säker driftsättning: beroende mellan två PR:er

**Driftsätt aldrig denna PR #530 innan motsvarande konfiguration i proxystacken är införd.** Se [Traefik-repots driftsättningsordning](https://github.com/Mr-cool08/traefik/blob/main/README.md) när dess ändring har mergats.

1. **Före koduppdatering:** pausa schemalagda uppdateringar, notera aktuell Git-revision och Compose-projektnamn. Spara befintlig `.env`, tidigare Compose och monterad Traefik-konfiguration separat. Verifiera en aktuell backup och kontrollera `docker network inspect jk_public_net`. Återanvänd existerande datavolymer och projektnamn.
2. **Förbered gemensam Traefik först.** Läs in `dynamic/utbildningsintyg.yml` i den nya proxyn, där huvud- och MTA-STS-routrarna har `priority: 1`. Befintliga Docker-label-routrar har högre prioritet och fortsätter att hantera webbtrafik tills denna app uppdateras. Om en gammal proxy äger port 80/443 måste just den containern stoppas innan nya proxyn tar portarna; behåll gamla containern för rollback. Kontrollera huvuddomän, www, `/health`, MTA-STS och inloggning.
3. **Uppdatera sedan utbildningsintyg.se** till denna PR med **samma Compose-projektnamn, befintlig `.env` och volymer**. Kör `docker compose config --quiet`. Kontrollera att `app` får nätverksaliaset `utbildningsintyg-web` och att `db_net` fortfarande är separat. Återskapa endast appcontainern om det behövs, exempelvis `docker compose up -d --no-deps app`.
4. **Verifiera central routing:** kontrollera `https://utbildningsintyg.se/health` och `https://www.utbildningsintyg.se/health` (HTTP 200), MTA-STS-policyn på `https://mta-sts.utbildningsintyg.se/.well-known/mta-sts.txt`, 404 för annan sökväg på MTA-STS-domänen, rätt TLS-certifikat och headers samt fungerande inloggning och uppladdningar. Kontrollera accessloggarna i den gemensamma proxyn.
5. Återuppta uppdateringsjobb först efter lyckad verifiering. Ta bort gammal proxycontainer först efter att återställningsfönstret stängts.

Undvik `docker compose down -v`, `docker volume prune` och nya Compose-projektnamn under hela migreringen. De kan påverka databasen och andra tjänster på den delade värden.

### Återställning

Om ett fel uppstår **före** uppdateringen av appen, behåll de befintliga Docker-labelsen och återställ vid behov gamla proxyn efter att frigjort port 80/443.

Om felet uppstår **efter** appuppdateringen, återställ föregående Git-revision och Compose-fil för appen (med samma projektnamn, `.env` och volymer) och återskapa enbart appcontainern. Den gamla routingen via Docker-labels återkommer då och har högre prioritet än `@file`-routrarna. Kontrollera alla tre domäner, TLS, MTA-STS och inloggning. Återställ aldrig databasen bara för att proxykonfigurationen ändrats.

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

På en delad Docker-värd hanteras systemuppgraderingar separat. Låt `ENABLE_OS_UPGRADE` och `CHECK_OS_UPDATES` vara avstängda vid ordinarie JK-uppdateringar. Den manuella åtgärden `prune-volumes` gäller hela Docker-värden och ska inte användas vid proxybytet.

Uppdateringssekvens:

```bash
python scripts/update_app.py
```

På Linux-servrar där `crontab` finns installerat säkerställer skriptet också att månadsjobbet för `expiry_reminder` finns inlagt en gång, utan dubbletter.

## HTTP på dev-servern utan port 443

För publik HTTPS hanterar den externa Traefik-stacken port 443 och origin-certifikat.
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
Följande startar HTTP-proxyn på dev-servern när värdporten är ledig. Bindningen begränsas till serverns LAN-adress:

```bash
DEV_MODE=true DEV_HTTP_BIND_IP=192.168.10.116 docker compose -f docker-compose.yml --profile dev-http config --quiet
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

`update_app.py` väljer `dev_http` endast vid exakt `DEV_MODE=true`. I produktion sköter den externa stacken HTTPS.

Återställning av denna dev-åtgärd: `docker compose -f docker-compose.yml stop dev_http`.
Det återgår till läget utan extern HTTP-åtkomst och ändrar inga volymer.
Vid ett avsiktligt byte till produktionsdrift måste dev-proxyn först stoppas;
produktionsdrift använder `DEV_MODE=false` och kräver fungerande port 443 och TLS.

## Vid publik Cloudflare-drift

Se även:

- [PUBLIC_DEPLOYMENT_CLOUDFLARE.md](PUBLIC_DEPLOYMENT_CLOUDFLARE.md)
- [../deploy/mta-sts/README.md](../deploy/mta-sts/README.md)

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
