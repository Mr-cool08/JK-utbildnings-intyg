#  Stabil Python (byt version om du vill)
FROM python:3.12-alpine3.20

# Installera systempaket
RUN apk add --no-cache tini bash curl \
    && addgroup -S app && adduser -S -G app app

WORKDIR /app

# Kopiera beroenden först (bättre cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

# Kopiera projektet
COPY . .

# Skapa och äg kataloger
RUN mkdir -p /app/uploads /app/logs /config \
    && cp .example.env /config/.env || true \
    && chown -R app:app /app /config /app/uploads /app/logs

# Miljö
ENV HTTP_PORT=80 \
    HTTPS_PORT=443 \
    PYTHONUNBUFFERED=1

# Hälsokontroll (antag /health i din app – annars ändra)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=5 \
  CMD curl -fsS http://127.0.0.1:${HTTP_PORT}/health || exit 1

# Exponera höga portar (mappa 80:8080, 443:8443 vid körning)
EXPOSE 80 443

# Entrypoint med korrekt signalhantering
ENTRYPOINT ["/sbin/tini","--"]
CMD ["./entrypoint.sh"]
