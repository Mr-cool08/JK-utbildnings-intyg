# Deployment

This project ships with a Docker setup and a GitHub Actions workflow that automatically builds a container image and publishes it to the GitHub Container Registry (GHCR) and Docker Hub.

## Prerequisites

- Docker or Docker Desktop installed

## Local development

You can build and run the container locally with Docker Compose:

```bash
docker compose up --build
```

The app will be available on <http://localhost:80>.

## Production deployment

Images are built and pushed to GHCR and Docker Hub on every push to the `main` branch. Run the latest image as follows:

```bash
docker pull ghcr.io/mr-cool08/jk-utbildnings-intyg:latest

docker run -d -p 80:80 \
  -v env_data:/config \
  -v uploads_data:/app/uploads \
  -v db_data:/data \
  -v logs_data:/app/logs \
  -v /home/client_52_3/certs:/certs \
  ghcr.io/mr-cool08/jk-utbildnings-intyg:latest
```

The named volumes are created automatically if they do not exist. On first
start the container copies `.example.env` into the `env_data` volume as `.env`.
Edit this file and restart the container to update environment variables.

Place your Cloudflare certificate and key in `/home/client_52_3/certs` and
reference them in `.env` via `CLOUDFLARE_CERT_PATH=/certs/cert.pem` and
`CLOUDFLARE_KEY_PATH=/certs/key.pem`.

If you later change any values in the `.env` file, restart the container so the new configuration takes effect.

