<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Deployment

Det här projektet använder i dagsläget **en gemensam `docker-compose.yml`** för både lokal körning och serverdrift.

## Förberedelser

1. Vid nyinstallation, kopiera `.example.env` till `.env`. Vid migrering, behåll serverns befintliga `.env`.
2. Fyll i minst databas-, admin- och SMTP-inställningar.
3. Kontrollera att det externa Docker-nätverket `jk_tunnel_net` finns på värden där gemensam `cloudflared` körs. Skapa det vid behov en gång med `docker network create jk_tunnel_net`. Även en separat dev-värd behöver skapa ett lokalt nät med detta namn för att Compose-konfigurationen ska kunna startas (ingen fungerande tunnel krävs för `dev_http`). Se migreringsordningen nedan.

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

- `app` nås internt på port **80** via `jk_tunnel_net` på adressen `http://utbildningsintyg:80`; ingen host-port är publicerad.
- `postgres` har **ingen** publicerad host-port. Databasen finns endast på `db_net` tillsammans med appen och backup-tjänsterna.
- `expiry_reminder` använder `db_net` och ett eget `worker_net` för utgående SMTP.
- `dev_http` kan publicera `${DEV_HTTP_BIND_IP:-127.0.0.1}:80:80` i utvecklingsprofilen och är enbart ansluten till lokala `dev_net`.
- `vscode` kan publicera `${VSCODE_BIND_IP:-127.0.0.1}:8087:8080` i sin utvecklingsprofil, ansluten till `dev_net`.

Exponera inte PostgreSQL eller appens HTTP-port direkt på värden. För databasadministration: `docker compose exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'`.

## Fail2ban

`fail2ban` läser värdens SSH-logg `/var/log/auth.log` och blockerar efter fem matchande fel inom tio minuter i en timme. Före start måste den lokala filen `deploy/fail2ban/ssh-access.local` skapas med administrationsadress och SSH-port. Följ [driftsättningsguiden för Fail2ban](../deploy/fail2ban/README.md) för förkontroll, säker aktivering och verifiering.

Publik webbtrafik bör i stället filtreras av Cloudflare och serverns brandvägg, så att fail2ban inte behöver vara primärt webbskydd för HTTP/HTTPS.

## Cloudflare Tunnel: routing och SSL sköts centralt

Detta projekt innehåller **inte någon publik Traefik-proxy**. Den gemensamma [Cloudflare Tunnel-infrastrukturen](https://github.com/Mr-cool08/infrastruktur_JK) kör `cloudflared` i en egen Compose-stack. Cloudflare hanterar externa certifikat, DNS och publicerade hostnamn.

- Webbcontainern `app` ansluter till externt `jk_tunnel_net` med aliaset `utbildningsintyg` och lyssnar internt på port 80.
- Publicerade Cloudflare-rutter: `utbildningsintyg.se` och `www.utbildningsintyg.se` → `http://utbildningsintyg:80`.
- MTA-STS: `mta-sts.utbildningsintyg.se` → samma service för `/.well-known/mta-sts.txt`. Begränsa den publicerade rutten till denna path och verifiera att andra sökvägar ger 404.
- `postgres` ligger endast på `db_net`; `expiry_reminder` ansluter inte till tunnelnätet men kan nå utgående SMTP via `worker_net`.
- Ingen publik TLS-konfiguration eller Traefik-labels behöver finnas i appens Compose. Intern HTTP mellan `cloudflared` och `app` används på samma Docker-värd. För olika servrar krävs separat bedömning av TLS på sista hoppen.
- Behåll `PREFERRED_URL_SCHEME=https` och `SESSION_COOKIE_SECURE=true`; verifiera `TRUSTED_PROXY_COUNT`, klient-IP och rätt HTTPS-redirects.
- Säkerhetsheaders, uppladdningsgränser och andra tidigare Traefik-middlewares måste hanteras i appen eller i Cloudflare, inte antas följa med automatiskt.

Se också [den kompletta Cloudflare-guiden](PUBLIC_DEPLOYMENT_CLOUDFLARE.md).

### Säker migrering till Cloudflare Tunnel

**Merga/driftsätt inte denna PR #530 förrän Cloudflare Tunnel kan nå nätverket `jk_tunnel_net`.** Ett fungerande Kursplan-upplägg innebär inte automatiskt att Utbildningsintygets hostname är konfigurerat.

1. **Förbered:** notera aktuellt Compose-projektnamn, Git-revision, fungerande `.env`, befintliga tjänster och nätverk. Verifiera databasbackup och behåll befintliga volymer, särskilt `jk-utbildnings-intyg_pgdata`.
2. **Kontrollera infrastrukturen:** `docker network inspect jk_tunnel_net`, och se att gemensam `cloudflared` ansluter till nätverket. Konfigurera tre publicerade hostnamn/rutter i Cloudflare inklusive MTA-STS; kontrollera DNS och edge-certifikat.
3. **Planera avbrott:** om gammal lokal Traefik fortfarande serverar trafik på 80/443 ska den tas ur drift kontrollerat, utan att ändra databasvolymer. Stäng inte av fungerande routing innan den nya är verifierbar.
4. **Uppdatera appen:** använd **samma Compose-projektnamn**, befintlig `.env` och volymer. Kör `docker compose -f docker-compose.yml config --quiet` och `docker compose -f docker-compose.yml up -d --build` vid planerad migrering. Kontrollera att `app` ansluts med aliaset `utbildningsintyg`, och att PostgreSQL inte publiceras till hosten.
5. **Verifiera:** testa `https://utbildningsintyg.se/health`, `https://www.utbildningsintyg.se/health`, `https://mta-sts.utbildningsintyg.se/.well-known/mta-sts.txt`, 404 för andra vägar på MTA-STS-domänen, korrekt HTTPS, säkerhetsheaders, inloggning, filuppladdningar och e-postutskick. Kontrollera också databasbackup.
6. **Städa först efter godkänd verifiering:** frigör gamla 80/443-bindningar och tidigare Traefik-filer när återställningsmöjlighet inte längre behövs. Återuppta uppdateringsjobb sist.

Undvik `docker compose down -v`, `docker volume prune` och byte av Compose-projektnamn. Förlust av projektnamn kan innebära att olika namngivna volymer används. En extern nätverks- och DNS-flytt är **inte** ett skäl att återställa eller återskapa PostgreSQL-data.

### Återställning

Vid fel: återställ tidigare körande Git-revision/Compose-definition i **samma projekt**, och växla DNS/rutt tillbaka till den tidigare fungerande proxyn först när den är igång. Testa därefter huvuddomän, www, MTA-STS, inloggning och databaskoppling. Återställ inte databasen enbart för att routningen har ändrats.

## PostgreSQL – endast internt

PostgreSQL 16 och dess befintliga namngivna volym behålls, men databasen exponeras inte längre som `127.0.0.1:1543`. Adminåtkomst sker med exempelvis:

~~~bash
docker compose exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
~~~

Om annan programvara på värden tidigare har använt `127.0.0.1:1543` måste den migreras till en säker alternativ anslutning **innan** porten tas bort i produktion.

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

På en delad Docker-värd hanteras systemuppgraderingar separat. Låt `ENABLE_OS_UPGRADE` och `CHECK_OS_UPDATES` vara avstängda vid ordinarie JK-uppdateringar. Den manuella åtgärden `prune-volumes` gäller hela Docker-värden och ska inte användas vid tunnelmigreringen.

Uppdateringssekvens:

```bash
python scripts/update_app.py
```

På Linux-servrar där `crontab` finns installerat säkerställer skriptet också att månadsjobbet för `expiry_reminder` finns inlagt en gång, utan dubbletter.

## HTTP på dev-servern utan port 443

För publik HTTPS hanterar Cloudflare edge-certifikatet och tunneln. Ingen publik port 443 eller origin-certifikat behövs för denna Compose-stack.
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

`update_app.py` väljer `dev_http` endast vid exakt `DEV_MODE=true`. I produktion sköter Cloudflare Tunnel HTTPS. På dev-värden måste nätverket `jk_tunnel_net` finnas eftersom appen också deklarerar det som externt, men den lokala HTTP-proxyn använder endast `dev_net`.

Återställning av denna dev-åtgärd: `docker compose -f docker-compose.yml stop dev_http`.
Det återgår till läget utan extern HTTP-åtkomst och ändrar inga volymer.
Vid ett avsiktligt byte till produktionsdrift måste dev-proxyn först stoppas;
produktionsdrift använder `DEV_MODE=false` och kräver en fungerande Cloudflare Tunnel-rutt samt HTTPS-certifikat hos Cloudflare.

## Vid publik Cloudflare-drift

Se även:

- [PUBLIC_DEPLOYMENT_CLOUDFLARE.md](PUBLIC_DEPLOYMENT_CLOUDFLARE.md)
- [../deploy/mta-sts/README.md](../deploy/mta-sts/README.md)

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
