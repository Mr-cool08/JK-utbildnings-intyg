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

## Extern Traefik

| Inställning i proxystacken | Krav |
| --- | --- |
| Docker | Eget Compose-projektnamn. Anslut proxyn till samma befintliga `jk_public_net` som appen. Aktivera Docker-providern med åtkomst till rätt Docker-daemon och `exposedByDefault=false`. |
| Routing | Reservera routernamnen `app` och `app-mta-sts` samt tjänstenamnet `app` i Docker-providern. JK:s labels väljer containerns IP på `jk_public_net` och HTTP-port 80. |
| Entrypoints | `web` på 80 omdirigerar till HTTPS. Båda routrarna använder `websecure` på 443 med TLS. |
| Domäner | Huvudroutern tar `utbildningsintyg.se` och `www.utbildningsintyg.se`. `mta-sts.utbildningsintyg.se` matchar endast exakt `/.well-known/mta-sts.txt`. Appen levererar befintlig policy som text. |
| Loggar | Aktivera accesslogg och proxylogg i den externa stacken så att du kan följa anrop och upptäcka fel vid portbytet. |
| TLS | Läs befintligt certifikat och nyckel från nuvarande platser, skrivskyddat. Kontrollera namn och giltighet för alla tre värdar. Behåll Cloudflare Full (strict) och publik certifikatvalidering för MTA-STS. |
| Filprovider | Tillhandahåll `security-headers@file` på båda routrarna och dessutom `upload-buffer@file` på huvudroutern. Behåll HSTS 63072000 sekunder med subdomäner och preload, nosniff, no-referrer, frameDeny och Permissions-Policy för geolocation, microphone och camera (alla avstängda). Behåll uppladdningsgränsen 104857600 byte. |

### Migrering på produktionsservern

1. **Innan koden uppdateras**, pausa schemalagda uppdateringar. Anteckna gammal Git-revision, Compose-projektnamn, appens nätverk och volymnamn. Kontrollera senaste databasbackup. Spara gamla Compose-filen och hela `deploy/traefik/dynamic` separat. Den körande proxyn bevakar katalogen och kan tappa både TLS och middlewares redan vid en Git-uppdatering. Låt nuvarande checkout, certifikat, nycklar och loggvolym ligga kvar under provet.
2. Identifiera gamla proxyn med gamla projektets `docker compose ps -q traefik`. Kontrollera dess projekt- och tjänstlabels med `docker inspect <gammalt-id>`. Kontrollera med `docker network inspect jk_public_net` att nuvarande app är ansluten. Återanvänd det fysiska nätverket även om det har gamla Compose-labels. Om installationen använder ett annat nätverksnamn, avbryt före portbytet och planera appens nätverksbyte separat. Använd samma projektnamn för JK efter migreringen så att samma volymer används.
3. Förbered och provkör den externa proxyn i dess eget projekt med tillfälliga loopback-portar, exempelvis 127.0.0.1:8443 till 443 och 127.0.0.1:8080 till 80. Gamla proxyn behåller 80/443. Kontrollera via skyddad Traefik-status eller loggar att båda routrarna och `app@docker` laddats utan fel. Kontrollera att backend-IP tillhör appen på `jk_public_net`. Prova varje värd direkt mot provproxyn med rätt SNI och rätt CA, exempelvis:

   ```bash
   curl --resolve utbildningsintyg.se:8443:127.0.0.1 https://utbildningsintyg.se:8443/health
   curl --resolve www.utbildningsintyg.se:8443:127.0.0.1 https://www.utbildningsintyg.se:8443/health
   curl --resolve mta-sts.utbildningsintyg.se:8443:127.0.0.1 https://mta-sts.utbildningsintyg.se:8443/.well-known/mta-sts.txt
   ```

   Vid Cloudflare Origin CA, använd `--cacert` med dess betrodda CA-fil. Kräv HTTP 200, rätt policytext och säkerhetsheaders. Bekräfta att en annan sökväg på MTA-STS-värden ger 404 och att HTTP omdirigeras till HTTPS.
4. Först efter godkänt prov, stoppa just gamla containern med `docker stop <gammalt-id>`. Låt den finnas kvar för återställning. Publicera 80/443 i den externa stacken. Verifiera HTTPS på båda huvuddomänerna, `/health`, MTA-STS och inloggning utifrån och kontrollera att anropen syns i nya proxyns accesslogg.
5. Uppdatera nu JK:s checkout, behåll befintlig `.env` och kör `docker compose config --quiet`. Kontrollera med `docker compose config --services` och `docker network inspect jk_public_net`. Vid behov tillämpa endast appens ändring med `docker compose up -d --no-deps app`. Verifiera trafik och volymkopplingar igen. Återuppta ordinarie uppdateringar med den nya skriptversionen. När återställningsfönstret stängts, ta bort endast den verifierade stoppade containern med `docker rm <gammalt-id>`. Behåll gamla loggvolymen.

### Återställning

Vid fel före portbytet, behåll gamla proxyn i drift. Vid fel efter portbytet, frigör 80/443 i den externa stacken (återgå till dess testportar). Återställ vid behov gamla `deploy/traefik/dynamic` på exakt den monterade sökvägen från kopian. Starta `docker start <gammalt-id>`. Om containern redan avvecklats, återställ även gamla Compose-filen och kör `docker compose up -d --no-deps traefik` från ursprunglig katalog med ursprungligt projektnamn. Kontrollera alla tre domäner, certifikat, policytext och inloggning igen. Håll automatiska uppdateringar pausade tills felet är utrett. Inget steg kräver återläsning av databasen eller borttagning av nätverk eller volymer.

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
