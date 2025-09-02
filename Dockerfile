# Use a stable Python runtime as the base image
FROM python:3.12-alpine

# Set work directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Ensure runtime directories exist, seed configuration volume
RUN mkdir -p /data /app/uploads /config /certs \
    && cp .example.env /config/.env \
    && chmod +x entrypoint.sh
VOLUME ["/data", "/app/uploads", "/config"]

# Configure port, database, and default certificate locations
ENV PORT=8080 \
    DB_PATH=/data/database.db \
    PYTHONUNBUFFERED=1 \
    CLOUDFLARE_CERT_PATH=/certs/cert.pem \
    CLOUDFLARE_KEY_PATH=/certs/key.pem

EXPOSE 8080

# Run the application with optional Cloudflare certificates
CMD ["./entrypoint.sh"]
