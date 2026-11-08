<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Publik drift med Cloudflare

Den här guiden gäller nuvarande projektupplägg där `docker-compose.yml` används även för serverdrift.

## Förberedelser

- Du behöver en server med Docker och Docker Compose.
- Du behöver en domän som hanteras i Cloudflare.
- Du behöver en färdig `.env` med korrekta proxyinställningar.

## Rekommenderade miljövariabler

```env
TRUSTED_PROXY_COUNT=1
PREFERRED_URL_SCHEME=https
SESSION_COOKIE_SECURE=true
```

`TRUSTED_PROXY_COUNT=1` matchar att Traefik är den betrodda proxyn framför Flask.

## DNS-poster i Cloudflare

Skapa DNS-poster för värdnamnen som routas av den gemensamma Traefik-konfigurationen:

- `utbildningsintyg.se`
- `www.utbildningsintyg.se`
- `mta-sts.utbildningsintyg.se`

Aktivera proxyn i Cloudflare där det är relevant.

## TLS och certifikat

Den separata [gemensamma Traefik-stacken](https://github.com/Mr-cool08/traefik) äger certifikat, TLS och routing för alla berörda domäner, inklusive MTA-STS. Inga `ORIGIN_CERT_PATH`, `ORIGIN_KEY_PATH`, `TLS_CERT` eller `TLS_KEY` behövs i applikationens `.env`. Låt Traefik läsa privata nycklar från servern och använd Cloudflare **Full (strict)** där Cloudflare proxar HTTPS.

Verifiera att MTA-STS-adressen presenterar ett publikt betrott certifikat för externa e-postavsändare. Se [migreringsordningen](DEPLOYMENT.md#säker-driftsättning-beroende-mellan-två-prer).

## Starta tjänsterna

```bash
docker compose -f docker-compose.yml up -d --build
```

## Skydda origin-servern

Även om projektet publicerar vissa host-portar direkt bör publik trafik styras via Cloudflare och filtreras i brandvägg.

Brandväggsskript finns här:

```bash
sudo bash scripts/firewall/cloudflare-ufw.sh --dry-run
```

```bash
sudo bash scripts/firewall/cloudflare-ufw.sh --apply
```

## Verifiera

Kontrollera att Cloudflare ligger framför tjänsten:

```bash
curl -I https://utbildningsintyg.se
```

Du ska normalt se headers som pekar på Cloudflare.

Verifiera även MTA-STS:

```bash
curl -I https://mta-sts.utbildningsintyg.se/.well-known/mta-sts.txt
```

## Vanliga fallgropar

- Fel certifikatvägar i den externa proxyn
- Glömt att proxya `mta-sts`-subdomänen
- Brandväggen släpper fortfarande igenom direkt trafik till origin
- Felaktigt `TRUSTED_PROXY_COUNT`, vilket kan ge fel klient-IP eller felaktiga redirects

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
