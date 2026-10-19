# Copyright (c) Liam Suorsa and Mika Suorsa
#  Stabil Python (byt version om du vill)
FROM python:3.15.0-alpine3.24

# Installera systempaket + uppgradera säkerhetsfixar (inkl OpenSSL)
RUN apk update \
    && apk upgrade --no-cache \
    && apk add --no-cache tini bash curl libpq \
    && addgroup -S app && adduser -S -G app app

WORKDIR /app

# Kopiera beroenden först (bättre cache)
COPY requirements.txt .
# Bygg psycopgs C-variant så att libpq hittas utan byggverktyg på Alpine.
# YARA byggs också från källkod när en wheel saknas.
RUN apk add --no-cache --virtual .build-deps build-base libpq-dev \
    && python -m pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "psycopg[c]==$(python -c 'from importlib.metadata import version; print(version("psycopg"))')" \
    && apk del .build-deps \
    && python -m pip check \
    && python -c "import psycopg, psycopg2, yara; assert psycopg.pq.__impl__ == 'c'; assert yara.compile(source='rule smoke { condition: true }').match(data=b'test')"

# Kopiera projektet
COPY . .

# Kontrollera hela PDF-skanningen med en riktig, ofarlig PDF.
RUN python -c "import io; from PIL import Image; from services.pdf_scanner import scan_pdf_bytes; data = io.BytesIO(); Image.new('RGB', (10, 10), 'white').save(data, format='PDF'); assert scan_pdf_bytes(data.getvalue()).decision == 'ALLOW'"

# Skapa och äg kataloger
RUN sed -i 's/\r$//' /app/entrypoint.sh \
    && chmod +x /app/entrypoint.sh \
    && mkdir -p /app/uploads /app/logs /config \
    && cp .env /config/.env || true \
    && chown -R app:app /app /config /app/uploads /app/logs

# Miljö
ENV DEV_MODE=false \
    HTTP_PORT=80 \
    HTTPS_PORT=443 \
    PYTHONUNBUFFERED=1

# Hälsokontroll (antag /health i din app – annars ändra)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=5 \
  CMD curl --max-time 2 -fsS http://127.0.0.1:${HTTP_PORT}/health || exit 1

# Exponera höga portar (mappa 80:8080, 443:8443 vid körning)
EXPOSE 80 443

# Entrypoint med korrekt signalhantering
ENTRYPOINT ["/sbin/tini","--"]
CMD ["./entrypoint.sh"]
