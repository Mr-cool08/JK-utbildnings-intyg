<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Fristående failover med cron i Docker

Den här lösningen körs separat från huvudstacken och växlar Cloudflare DNS till en fallback-sida när huvudwebben eller Traefik slutar svara.

Fallback som används i exemplet:
`https://jk-utbildnings-intyg.onrender.com`

## Översikt

- En separat container kör `crond`.
- Varannan minut körs en hälsokontroll.
- Om huvudsida eller Traefik är nere pekas DNS om till fallback.
- När båda är friska pekas DNS tillbaka till primär target.

## 1) Lägg till variabler i `.env`

```env
# Hälso-URL:er
FAILOVER_MAIN_URL=https://utbildningsintyg.se/health
FAILOVER_TRAEFIK_URL=http://127.0.0.1:8080/ping

# Primär/fallback DNS-target
FAILOVER_PRIMARY_TARGET=utbildningsintyg.se
FAILOVER_FALLBACK_TARGET=jk-utbildnings-intyg.onrender.com

# Timeout i sekunder
FAILOVER_HTTP_TIMEOUT_SECONDS=8

# Cloudflare API
CLOUDFLARE_API_TOKEN=din_token
CLOUDFLARE_ZONE_ID=din_zone_id
CLOUDFLARE_RECORD_ID=ditt_record_id
```

## 2) Starta den fristående tjänsten

```bash
docker compose -f docker-compose.failover.yml up -d --build
```

## 3) Se loggar

```bash
docker compose -f docker-compose.failover.yml logs -f
```

## Viktigt

- Kör tjänsten på samma server men i separat compose-fil för att hålla den oberoende av huvudprogrammet.
- DNS-record i Cloudflare måste vara rätt record för domänen/subdomänen du vill växla.
- Lösningen kräver att Cloudflare API-token har behörighet att läsa/skriva DNS-records i zonen.

## Test av failover

1. Stoppa tillfälligt Traefik eller blockera hälsocheck-url.
2. Vänta upp till 2 minuter.
3. Kontrollera att DNS-target pekar mot `jk-utbildnings-intyg.onrender.com`.
4. Starta upp tjänster igen och verifiera automatisk återgång.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
