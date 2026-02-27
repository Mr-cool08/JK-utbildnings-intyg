<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Publik drift med Cloudflare (enkel guide)

Den här guiden är för produktion med Cloudflare framför appen.

## 1. Förbered

- Du behöver en server med Docker.
- Du behöver en domän i Cloudflare.
- Du behöver en `.env`-fil.

## 2. DNS i Cloudflare

Skapa poster för dina domäner och aktivera proxy (orange moln).

## 3. TLS

- Skapa Origin CA-certifikat i Cloudflare.
- Lägg certifikat och nyckel på servern.
- Sätt sökvägar i `.env`:
  - `ORIGIN_CERT_PATH`
  - `ORIGIN_KEY_PATH`

Sätt SSL-läge i Cloudflare till **Full (strict)**.

## 4. Starta produktion

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

## 5. Skydda origin

Begränsa inkommande trafik så bara Cloudflare får nå webbportar.

Script finns här:

```bash
sudo bash scripts/firewall/cloudflare-ufw.sh --apply
```

Testa först:

```bash
sudo bash scripts/firewall/cloudflare-ufw.sh --dry-run
```

## 6. Verifiera

Kontrollera att domänen svarar via Cloudflare:

```bash
curl -I https://DIN_DOMAN
```

Du ska se headers som `server: cloudflare`.

<!-- Copyright (c) Liam Suorsa and Mika Suorsa -->
