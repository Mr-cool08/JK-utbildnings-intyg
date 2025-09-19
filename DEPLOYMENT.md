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
  -v postgres_internal_data:/var/lib/postgresql/data \
  -v db_data:/data \
  -v logs_data:/app/logs \
  ghcr.io/mr-cool08/jk-utbildnings-intyg:latest
```

The named volumes are created automatically if they do not exist and reused if present. The
`postgres_internal_data` volume stores the bundled PostgreSQL instance that now starts automatically
whenever `DATABASE_URL` is empty (`BUNDLED_POSTGRES=auto`). Set `BUNDLED_POSTGRES=off` to skip the
internal database and fall back to SQLite (the `db_data` volume) or to provide your own
`DATABASE_URL`. On first start the container copies `.example.env` into the `env_data` volume as
`.env`. Edit this file and restart the container to update environment variables.

When you maintain PostgreSQL on another server, set `POSTGRES_HOST` (and, if necessary,
`POSTGRES_PORT`) in `.env` and leave `DATABASE_URL` empty. The entrypoint combines these values with
`POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB` to build the connection string, skipping the
bundled database entirely.

### Manual volume creation

If you prefer to create the named volumes yourself before starting the container, run:

```bash
docker volume create env_data
docker volume create uploads_data
docker volume create postgres_internal_data
docker volume create db_data
docker volume create logs_data
```

Then run the container and attach the volumes:

```bash
docker run -d --name jk_utbildnings_intyg \
  -p 80:80 -p 443:443 \
  -v env_data:/config \
  -v uploads_data:/app/uploads \
  -v postgres_internal_data:/var/lib/postgresql/data \
  -v db_data:/data \
  -v logs_data:/app/logs \
  -e DB_PATH=/data/database.db \
  ghcr.io/mr-cool08/jk-utbildnings-intyg:latest
```

Remove the `db_data` mapping (and optionally set `BUNDLED_POSTGRES=off`) if you do not plan to use
the SQLite fallback database.

### Portainer

To deploy the container with [Portainer](https://www.portainer.io/):

1. In Portainer, navigate to **Volumes** and create volumes named `env_data`, `uploads_data`, `postgres_internal_data`, `db_data`, and `logs_data`.
2. Add a new container (or stack) using the `ghcr.io/mr-cool08/jk-utbildnings-intyg:latest` image.
   - Map the volumes to `/config`, `/app/uploads`, `/var/lib/postgresql/data`, `/data`, and `/app/logs` respectively.
   - Set the environment variable `DB_PATH` to `/data/database.db` (only used when `BUNDLED_POSTGRES=off`).
   - Publish ports `80` and `443`.
3. Start the container. Portainer will reuse the existing volumes on subsequent runs.

To use your own TLS certificate, provide the PEM-encoded certificate and key via
`TLS_CERT` and `TLS_KEY` in `.env`. If no certificate is supplied a self-signed
one is generated automatically.

If you later change any values in the `.env` file, restart the container so the new configuration takes effect.

### Start the app together with PostgreSQL automatically

For hosts that prefer a separate PostgreSQL container instead of the bundled
database that now starts automatically, the repository includes
`scripts/start_postgres_stack.sh`. The helper script expects a populated `.env`
file (copied from `.example.env`) and launches both containers with matching
PostgreSQL credentials in one command:

```bash
./scripts/start_postgres_stack.sh
```

On its first run the script creates a Docker network plus volumes for uploads,
logs, SQLite fallbacks, and the PostgreSQL data directory. Afterwards it
provisions a `jk_utbildningsintyg_db` container using the official
`postgres:15-alpine` image and starts the application container with
`DATABASE_URL` pointed at that database. Subsequent executions reuse the same
resources, so the database contents survive restarts or upgrades. You can
override names and images by exporting variables such as `APP_IMAGE`,
`APP_CONTAINER`, or `POSTGRES_VOLUME` before invoking the script.

