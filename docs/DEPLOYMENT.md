<!-- # Copyright (c) Liam Suorsa -->
# Driftsättning

Den här guiden beskriver hur du kör applikationen med Docker lokalt samt hur du sätter upp produktion med Nginx, PostgreSQL och valfri Cloudflare-proxy.

## Förutsättningar

- Docker och Docker Compose
- En `.env`-fil baserad på `.example.env`

## Lokal Docker-utveckling

För en lokal utvecklingsstack använder du `docker-compose.yml`. Den startar app, demoapp, status-sida samt en PostgreSQL-container.

```bash
docker compose up --build
```

När stacken är igång:

- Appen: <http://localhost:8080>
- Demoapp: <http://localhost:8081>
- Statussida: <http://localhost:8082>

Vill du endast starta demoappen:

```bash
docker compose up --build app_demo
```

Behöver proxyn ansluta till ett redan existerande Docker-nätverk kan du sätta miljövariabeln `PUBLIC_NETWORK_NAME` innan `docker compose up` körs. Då används det angivna nätverket i stället för standardnamnet.

## Produktion med Docker Compose

Produktionstacken ligger i `docker-compose.prod.yml` och inkluderar Nginx, app, demoapp, status-sida, PostgreSQL, backup-jobb och valfri antiviruscontainer.

Antiviruscontainern kan även skicka varningsmejl när infekterade filer hittas. Konfigurera SMTP med `ANTIVIRUS_ALERT_EMAIL_TO`, `ANTIVIRUS_ALERT_EMAIL_FROM`, `ANTIVIRUS_ALERT_SMTP_HOST` samt eventuella inloggningsuppgifter (`ANTIVIRUS_ALERT_SMTP_USER`, `ANTIVIRUS_ALERT_SMTP_PASSWORD`). TLS styrs via `ANTIVIRUS_ALERT_SMTP_TLS` och standardporten är `587`.

1. **Skapa `.env`**
   ```bash
   cp .example.env .env
   ```
2. **Fyll i nödvändiga värden** för PostgreSQL och övriga tjänster.
3. **Starta stacken**
   ```bash
   docker compose -f docker-compose.prod.yml up -d --build
   ```

Nginx lyssnar på port 80/443 och vidarebefordrar trafik till appen.

### Beständig data i produktion

Standardstacken skapar volymer för:

- `env_data` – `.env`-filen som monteras till `/config`
- `app_logs` – applikationsloggar
- `nginx_logs` – proxyloggar
- `pgdata` – PostgreSQL-data
- `pgdata_backups` – databaskopior

Uppladdade filer lagras i `/app/uploads` i appcontainern. Om du vill göra uppladdningar beständiga, lägg till en volymmontering för `/app/uploads` i `docker-compose.prod.yml`.

### Portainer

Vill du driftsätta via Portainer kan du använda `docker-compose.prod.yml` som stack:

1. Skapa volymerna ovan.
2. Klistra in Compose-filen som stack och starta den.
3. Se till att `.env` finns och innehåller korrekta värden.

### Starta app + PostgreSQL med hjälpskript

Skriptet `scripts/start_postgres_stack.sh` startar en lokal PostgreSQL-container och appen i en gemensam stack. Det förutsätter att `.env` finns och är korrekt ifylld.

```bash
./scripts/start_postgres_stack.sh
```

Skriptet skapar nätverk och volymer första gången och återanvänder dem vid nästa körning.

## TLS och Cloudflare

Om du använder Cloudflare och Origin CA ska `ORIGIN_CERT_PATH` och `ORIGIN_KEY_PATH` peka på certifikatfilerna på värden. Se även [PUBLIC_DEPLOYMENT_CLOUDFLARE.md](PUBLIC_DEPLOYMENT_CLOUDFLARE.md) för en steg-för-steg-guide.
