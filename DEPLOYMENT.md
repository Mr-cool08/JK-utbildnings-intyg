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
  -v logs_data:/app/logs \
  ghcr.io/mr-cool08/jk-utbildnings-intyg:latest
```

The named volumes are created automatically if they do not exist and reused if present. On first start the container copies `.example.env` into the `env_data` volume as `.env`. Edit this file and restart the container to update environment variables. Provide the connection details for your external PostgreSQL server either in this `.env` file or via `docker run` environment variables such as `POSTGRES_HOST`, `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD`.

### Manual volume creation

If you prefer to create the named volumes yourself before starting the container, run:

```bash
docker volume create env_data
docker volume create uploads_data
docker volume create logs_data
```

Then run the container and attach the volumes:

```bash
docker run -d --name jk_utbildnings_intyg \
  -p 80:80 -p 443:443 \
  -v env_data:/config \
  -v uploads_data:/app/uploads \
  -v logs_data:/app/logs \
  ghcr.io/mr-cool08/jk-utbildnings-intyg:latest
```

### Portainer

To deploy the container with [Portainer](https://www.portainer.io/):

1. In Portainer, navigate to **Volumes** and create volumes named `env_data`, `uploads_data`, and `logs_data`.
2. Add a new container (or stack) using the `ghcr.io/mr-cool08/jk-utbildnings-intyg:latest` image.
   - Map the volumes to `/config`, `/app/uploads`, and `/app/logs` respectively.
   - Provide the external PostgreSQL credentials via environment variables (for example `POSTGRES_HOST`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`).
   - Publish ports `80` and `443`.

To use your own TLS certificate, provide the PEM-encoded certificate and key via `TLS_CERT` and `TLS_KEY` in `.env`. If no certificate is supplied a self-signed one is generated automatically.

If you later change any values in the `.env` file, restart the container so the new configuration takes effect.

### Start the app together with PostgreSQL automatically

For hosts that prefer running PostgreSQL in a dedicated container managed alongside the application, the repository includes `scripts/start_postgres_stack.sh`. The helper script expects a populated `.env` file (copied from `.example.env`) and launches both containers with matching PostgreSQL credentials in one command:

```bash
./scripts/start_postgres_stack.sh
```

On its first run the script creates a Docker network plus volumes for uploads and logs. Afterwards it provisions a `jk_utbildningsintyg_db` container using the official `postgres:15-alpine` image and starts the application container with `DATABASE_URL` pointed at that database. Subsequent executions reuse the same resources, so the database contents survive restarts or upgrades. You can override names and images by exporting variables such as `APP_IMAGE`, `APP_CONTAINER`, or `POSTGRES_VOLUME` before invoking the script.
