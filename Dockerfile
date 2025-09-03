# Use official Python runtime as a parent image
FROM python:3.14.0rc2-alpine3.22

# Set work directory
WORKDIR /app

# Install system packages and Python dependencies
RUN apk add --no-cache nginx openssl
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Ensure runtime directories exist, seed configuration volume
RUN mkdir -p /data /app/uploads /config /run/nginx /etc/nginx/certs \
    && cp .example.env /config/.env \
    && chmod +x entrypoint.sh
VOLUME ["/data", "/app/uploads", "/config"]

# Configure ports and database
ENV HTTPS_PORT=443 \
    HTTP_PORT=80 \
    DB_PATH=/data/database.db \
    PYTHONUNBUFFERED=1

EXPOSE 80 443

# Run the application with optional TLS certificates
CMD ["./entrypoint.sh"]
