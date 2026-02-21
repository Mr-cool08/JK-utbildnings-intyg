<!-- # Copyright (c) Liam Suorsa and Mika Suorsa -->
# Publik driftsättning med Cloudflare (Full strict)

Den här guiden beskriver hur du driftsätter JK Utbildningsintyg bakom Cloudflare
med en lokal omvänd proxy (Traefik) och låser origin till Cloudflare-IP:er.

## 1. Förbered Cloudflare

1. Lägg till din domän i Cloudflare och aktivera den orange moln-ikonen (proxy).
2. Gå till **SSL/TLS → Origin Server** och skapa ett **Origin Certificate**.
3. Spara certifikatet och privat nyckel som två separata filer i PEM-format.
4. Gå till **SSL/TLS → Overview** och välj **Full (strict)**.

## 2. Lägg certifikatet på origin

Skapa en säker plats på origin-servern och kopiera filerna dit:

```bash
sudo mkdir -p /etc/ssl/cloudflare
sudo chmod 700 /etc/ssl/cloudflare
sudo cp origin.crt /etc/ssl/cloudflare/origin.crt
sudo cp origin.key /etc/ssl/cloudflare/origin.key
sudo chmod 600 /etc/ssl/cloudflare/origin.*
```

## 3. Konfigurera .env och starta stacken

1. Skapa `.env` från `.example.env` och fyll i riktiga värden.
2. Sätt `ORIGIN_CERT_PATH` och `ORIGIN_KEY_PATH` till filerna från steget ovan.
3. Säkerställ att `TRUSTED_PROXY_COUNT=1` (Traefik är enda betrodda proxyn mot Flask).
4. Uppdatera Cloudflare IP-listor vid behov:
   ```bash
   ./scripts/generate_cloudflare_ips.sh
   ```

Starta produktion med docker compose:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

### Loggar via volym

Följ loggar direkt från volymen:

```bash
docker compose -f docker-compose.prod.yml exec app tail -f /app/logs/gunicorn-access.log
docker compose -f docker-compose.prod.yml exec traefik tail -f /var/log/traefik/access.log
```

## 4. Aktivera brandvägg för Cloudflare-IP:er

Kör UFW-scriptet i läget `--apply` när du är redo:

```bash
sudo bash scripts/firewall/cloudflare-ufw.sh --apply
```

Testa först i dry-run om du vill se kommandona:

```bash
sudo bash scripts/firewall/cloudflare-ufw.sh --dry-run
```

**Viktigt:** Scriptet lämnar port 22 (SSH) öppen men du bör låsa ner SSH
ytterligare vid behov (t.ex. till en specifik IP).

## 5. Verifiering

### Kontrollera att Cloudflare används

Byt ut `DIN_DOMÄN` mot din riktiga domän (t.ex. `example.com`):

```bash
curl -I https://DIN_DOMÄN
```

Du ska se headers som `server: cloudflare` och `cf-ray`.

### Kontrollera att origin är låst

Byt ut `ORIGIN_IP` mot serverns riktiga IP-adress eller hostname
(t.ex. `203.0.113.10` eller `origin.example.com`):

```bash
curl -I http://ORIGIN_IP
curl -Ik https://ORIGIN_IP
```

Begäran ska blockeras (timeout om UFW stoppar, eller 403/401 om Traefik svarar).

### Kontrollera korrekt klient-IP i loggar

Hämta en rad från access-loggen och säkerställ att första IP-adressen är den
verkliga klienten (inte Cloudflare-IP):

```bash
docker compose -f docker-compose.prod.yml exec app tail -n 5 /app/logs/gunicorn-access.log
```

Om IP-adressen i loggen är en Cloudflare-adress, kontrollera att:

- `TRUSTED_PROXY_COUNT=1` i `.env`
- Traefik skickar `X-Forwarded-For`
- Cloudflare-proxy är aktiverad (orange moln)
