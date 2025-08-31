# Use official Python runtime as a parent image
FROM python:3.14.0rc2-alpine3.22

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

# Configure port and default database location
ENV PORT=8080 \
    DB_PATH=/data/database.db \
    PYTHONUNBUFFERED=1

EXPOSE 8080

# Run the application with optional Cloudflare certificates
CMD ["./entrypoint.sh"]

