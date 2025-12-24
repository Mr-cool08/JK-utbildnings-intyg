# JK Utbildningsintyg – Enkel wiki

## Översikt

JK Utbildningsintyg är en webbapplikation för hantering av utbildningsintyg.
Applikationen körs i Docker och använder en PostgreSQL-databas.

## Snabblänkar

- Drift: `docs/DEPLOYMENT.md`
- Cloudflare: `docs/PUBLIC_DEPLOYMENT_CLOUDFLARE.md`
- Produktionsguide: `docs/PRODUKTION_SETUP.md`
- Portainer Stack: `docs/PRODUKTION_SETUP.md` (Steg 9)
- Säkerhet: `SECURITY.md`

## Arkitektur

- **Flask/Gunicorn**: applikationsserver
- **Nginx**: omvänd proxy och TLS
- **PostgreSQL**: databas
- **Docker**: körmiljö och isolering

## Miljövariabler (vanliga)

- `POSTGRES_HOST`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `TRUSTED_PROXY_COUNT`

## Driftsättning

Rekommenderad metod är `docker-compose.prod.yml`:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

## Loggar

```bash
docker compose -f docker-compose.prod.yml exec app tail -f /app/logs/gunicorn-access.log
docker compose -f docker-compose.prod.yml exec nginx tail -f /var/log/nginx/access.log
```

## Felsökning

- **502/504**: kontrollera att app-containern svarar.
- **Databasfel**: verifiera `.env` och PostgreSQL-anslutning.
- **Fel klient-IP**: kontrollera `TRUSTED_PROXY_COUNT=1`.

## FAQ

**Hur uppdaterar jag till senaste versionen?**

```bash
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

**Var finns miljöfilen?**

Den ligger i volymen `env_data` och heter `.env`.
