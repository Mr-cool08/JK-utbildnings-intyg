# Deployment

This project ships with a Docker setup and a GitHub Actions workflow that automatically builds a container image and publishes it to the GitHub Container Registry (GHCR) and Docker Hub.

## Prerequisites

- Docker or Docker Desktop installed

## Local development

You can build and run the container locally with Docker Compose:

```bash
docker compose up --build
```

The app will be available on <https://localhost> and <http://localhost>.

## Production deployment

Images are built and pushed to GHCR and Docker Hub on every push to the `main` branch. Run the latest image as follows:

```bash
docker pull ghcr.io/mr-cool08/jk-utbildnings-intyg:latest

docker run -d -p 80:80 -p 443:443 \
  -v env_data:/config \
  -v uploads_data:/app/uploads \
  -v db_data:/data \
  -v logs_data:/app/logs \
  ghcr.io/mr-cool08/jk-utbildnings-intyg:latest
```

The named volumes are created automatically if they do not exist and reused if present. On first
start the container copies `.example.env` into the `env_data` volume as `.env`.
Edit this file and restart the container to update environment variables.

To use your own TLS certificate, provide the PEM-encoded certificate and key via
`TLS_CERT` and `TLS_KEY` in `.env`. If no certificate is supplied a self-signed
one is generated automatically.

If you later change any values in the `.env` file, restart the container so the new configuration takes effect.

