# Produktionsguide (superförklaring)

Det här dokumentet beskriver en komplett produktionssättning av JK Utbildningsintyg
med Docker, extern PostgreSQL, TLS och Cloudflare. Guiden är steg-för-steg och
innehåller kontrollpunkter så att du kan verifiera att allt fungerar.

## Innehåll

- Översikt
- Förutsättningar
- Rekommenderad arkitektur
- Steg 1: Förbered servern
- Steg 2: Hämta och kör applikationen
- Steg 3: Konfigurera miljövariabler (.env)
- Steg 4: TLS och certifikat
- Steg 5: Cloudflare (Full strict)
- Steg 6: Brandvägg och origin-låsning
- Steg 7: Drift, loggar och övervakning
- Steg 8: Uppgraderingar
- Steg 9: Portainer (Stack) – superdetaljerad setup
- Felsökning
- Checklista för produktion

## Översikt

Målet är att köra applikationen bakom en omvänd proxy med TLS samt låsa origin
så att endast Cloudflare når den. En typisk uppsättning är:

1. Cloudflare proxy (orange moln)
2. Nginx-container (från `docker-compose.prod.yml`)
3. Applikationscontainer (Gunicorn + Flask)
4. Extern PostgreSQL (egen server eller container)

## Förutsättningar

- Linux-server med Docker och Docker Compose
- En domän som du äger och kan konfigurera i Cloudflare
- Tillgång till en PostgreSQL-databas (extern eller container)
- Grundläggande vana vid SSH

## Rekommenderad arkitektur

- **Cloudflare**: hanterar TLS mot besökare och DDoS-skydd.
- **Origin**: tar endast emot trafik från Cloudflare-IP-adresser.
- **Docker**: kör applikation och Nginx med fasta volymer för data och loggar.

## Steg 1: Förbered servern

1. Installera Docker och Docker Compose.
2. Skapa en katalog för projektet:

```bash
mkdir -p /opt/jk-utbildnings-intyg
cd /opt/jk-utbildnings-intyg
```

3. Klona repot och gå in i katalogen:

```bash
git clone <REPO_URL>
cd jk-utbildnings-intyg
```

## Steg 2: Hämta och kör applikationen

Det finns två alternativ:

### Alternativ A: Kör senaste image från registry

```bash
docker pull ghcr.io/mr-cool08/jk-utbildnings-intyg:latest
```

Kör med volymer:

```bash
docker run -d -p 80:80 -p 443:443 \
  -v env_data:/config \
  -v uploads_data:/app/uploads \
  -v logs_data:/app/logs \
  ghcr.io/mr-cool08/jk-utbildnings-intyg:latest
```

### Alternativ B: Kör via docker-compose (rekommenderat för Cloudflare)

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

## Steg 3: Konfigurera miljövariabler (.env)

1. Kopiera `.example.env` till `.env`.
2. Fyll i riktiga värden, särskilt för PostgreSQL:
   - `POSTGRES_HOST`
   - `POSTGRES_DB`
   - `POSTGRES_USER`
   - `POSTGRES_PASSWORD`
3. Starta om tjänsterna om du ändrar `.env`.

## Steg 4: TLS och certifikat

Du kan använda egna certifikat eller Cloudflare Origin Certificate.

- För Cloudflare rekommenderas **Origin Certificate**.
- Lägg certifikaten på origin:

```bash
sudo mkdir -p /etc/ssl/cloudflare
sudo chmod 700 /etc/ssl/cloudflare
sudo cp origin.crt /etc/ssl/cloudflare/origin.crt
sudo cp origin.key /etc/ssl/cloudflare/origin.key
sudo chmod 600 /etc/ssl/cloudflare/origin.*
```

- Sätt variablerna i `.env`:
  - `ORIGIN_CERT_PATH=/etc/ssl/cloudflare/origin.crt`
  - `ORIGIN_KEY_PATH=/etc/ssl/cloudflare/origin.key`

## Steg 5: Cloudflare (Full strict)

1. Lägg till domänen i Cloudflare.
2. Aktivera orange moln (proxy) för DNS-posten.
3. Gå till **SSL/TLS → Origin Server** och skapa certifikat.
4. Gå till **SSL/TLS → Overview** och välj **Full (strict)**.

För mer detaljer se: `docs/PUBLIC_DEPLOYMENT_CLOUDFLARE.md`.

## Steg 6: Brandvägg och origin-låsning

Uppdatera Cloudflare-IP-listor och lås origin:

```bash
./scripts/generate_cloudflare_ips.sh
sudo bash scripts/firewall/cloudflare-ufw.sh --apply
```

Kontrollera att endast Cloudflare når origin genom att testa direkt mot origin-IP.

## Steg 7: Drift, loggar och övervakning

### Loggar

```bash
docker compose -f docker-compose.prod.yml exec app tail -f /app/logs/gunicorn-access.log
docker compose -f docker-compose.prod.yml exec nginx tail -f /var/log/nginx/access.log
```

### Hälsokontroll

- Kontrollera att domänen svarar:

```bash
curl -I https://DIN_DOMÄN
```

Du ska se headers som `server: cloudflare` och `cf-ray`.

## Steg 8: Uppgraderingar

1. Hämta senaste image eller bygg om.
2. Starta om containrarna:

```bash
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

## Steg 9: Portainer (Stack) – superdetaljerad setup

Den här delen visar exakt hur du sätter upp produktion via **Portainer Stack**
med `docker-compose.prod.yml`. Guiden utgår från att du kör Portainer på samma
host som Docker (local endpoint).

### 9.1 Förbered filer och miljö

1. **Skapa en katalog för stacken** på servern (exempel):

```bash
mkdir -p /opt/jk-utbildnings-intyg
cd /opt/jk-utbildnings-intyg
```

2. **Kopiera projektfilerna** till servern (git clone eller annan metod).

3. **Skapa `.env`** från `.example.env` och fyll i riktiga värden:

```bash
cp .example.env .env
```

4. **Kontrollera att följande variabler är satta**:

- `POSTGRES_HOST`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `TRUSTED_PROXY_COUNT=1`

5. **Om du använder Cloudflare Origin Certificate**, kopiera certifikaten till
servern (exempel):

```bash
sudo mkdir -p /etc/ssl/cloudflare
sudo chmod 700 /etc/ssl/cloudflare
sudo cp origin.crt /etc/ssl/cloudflare/origin.crt
sudo cp origin.key /etc/ssl/cloudflare/origin.key
sudo chmod 600 /etc/ssl/cloudflare/origin.*
```

Sätt i `.env`:

- `ORIGIN_CERT_PATH=/etc/ssl/cloudflare/origin.crt`
- `ORIGIN_KEY_PATH=/etc/ssl/cloudflare/origin.key`

### 9.2 Skapa volymer i Portainer

1. Öppna Portainer → **Volumes**.
2. Skapa följande volymer (exakta namn):
   - `env_data`
   - `uploads_data`
   - `logs_data`

> # Dessa volymer används av stacken för miljöfil, uppladdningar och loggar.

### 9.3 Skapa en ny Stack

1. Gå till Portainer → **Stacks** → **Add stack**.
2. Ge stacken ett namn, t.ex. `jk-utbildnings-intyg`.
3. Välj **Repository** eller **Web editor**.

#### Alternativ A: Web editor (snabbt)

1. Öppna `docker-compose.prod.yml` lokalt och kopiera hela innehållet.
2. Klistra in i Portainers **Web editor**.
3. Under **Environment variables**, lägg till variablerna som saknas i
   `docker-compose.prod.yml` (minst databasen).

#### Alternativ B: Repository (rekommenderat)

1. Välj **Repository** och fyll i:
   - Repository URL: `https://github.com/<ORG>/<REPO>.git`
   - Reference: `main`
   - Compose path: `docker-compose.prod.yml`
2. Under **Environment variables**, ange samma värden som i `.env`.
   - Exempel: `POSTGRES_HOST`, `POSTGRES_DB`, `POSTGRES_USER`,
     `POSTGRES_PASSWORD`, `TRUSTED_PROXY_COUNT=1`
3. Om du använder Cloudflare-certifikat, lägg till:
   - `ORIGIN_CERT_PATH=/etc/ssl/cloudflare/origin.crt`
   - `ORIGIN_KEY_PATH=/etc/ssl/cloudflare/origin.key`

> # Portainer läser inte automatiskt `.env` om du kör via Repository.  
> # Du måste ange variablerna i Portainers UI eller använda en env-fil via
> # "Advanced mode" om din Portainer-version stödjer det.

### 9.4 Starta stacken

1. Klicka **Deploy the stack**.
2. Vänta tills både `app` och `nginx` är **running**.

### 9.5 Verifiera stacken

1. I Portainer → **Containers**, kontrollera att båda containrarna kör.
2. Öppna loggar:
   - `app`: kontrollera att Flask/Gunicorn startat.
   - `nginx`: kontrollera att Nginx startat utan TLS-fel.
3. Testa med:

```bash
curl -I https://DIN_DOMÄN
```

Du ska se `server: cloudflare` och `cf-ray` om Cloudflare är aktivt.

### 9.6 Uppdateringar via Portainer

1. Gå till **Stacks** → välj din stack.
2. Klicka **Update the stack**.
3. Välj **Pull latest image** (om tillgängligt).
4. Klicka **Update**.

### 9.7 Vanliga fel i Portainer

- **Stack deployar men appen svarar inte**:
  - Kontrollera att `POSTGRES_*` är rätt och att databasen är nåbar.
- **Nginx TLS-fel**:
  - Kontrollera att `ORIGIN_CERT_PATH` och `ORIGIN_KEY_PATH` pekar på filer
    som finns på hosten.
- **Fel klient-IP i loggar**:
  - Kontrollera `TRUSTED_PROXY_COUNT=1`.

## Felsökning

- **Tom sida eller 502**: kontrollera Nginx-loggar och att app-containern kör.
- **Fel klient-IP**: kontrollera `TRUSTED_PROXY_COUNT=1`.
- **Databasfel**: verifiera PostgreSQL-anslutningsuppgifter i `.env`.

## Checklista för produktion

- [ ] Domänen är proxad via Cloudflare (orange moln)
- [ ] SSL/TLS är **Full (strict)**
- [ ] `ORIGIN_CERT_PATH` och `ORIGIN_KEY_PATH` är satta
- [ ] `TRUSTED_PROXY_COUNT=1`
- [ ] Brandvägg tillåter endast Cloudflare-IP:er
- [ ] Loggar roterar och disk tar inte slut
- [ ] Backup för PostgreSQL är aktiverad
