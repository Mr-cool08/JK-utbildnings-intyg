# Deployment

This project ships with a Docker setup and a GitHub Actions workflow that automatically builds a container image and publishes it to the GitHub Container Registry (GHCR) and Docker Hub.

## Prerequisites

- Docker or Docker Desktop installed
- A `.env` file containing the required environment variables such as `secret_key`, `smtp_server`, `smtp_user`, etc.

## Local development

You can build and run the container locally with Docker Compose:

```bash
docker compose up --build
```

The app will be available on http://localhost:8000.

## Production deployment

Images are built and pushed to GHCR and Docker Hub on every push to the `main` branch. The latest image can be pulled and started as follows (replace `OWNER` with your GitHub username or organisation in lowercase and `DOCKERHUB_USER` with your Docker Hub username):

```bash
docker pull ghcr.io/mr-cool08/jk-utbildnings-intyg:latest

# start the container with persistent named volumes
docker run -d -p 8000:8000 \
  -v env_data:/config \
  -v uploads_data:/app/uploads \
  -v db_data:/data \
  -v logs_data:/app/logs \
  ghcr.io/mr-cool08/jk-utbildnings-intyg:latest
```

The `docker run` command above creates the four volumes automatically if they do not already exist. Populate the configuration volume with your `.env` file before the first run:

```bash
docker run --rm -v env_data:/config -v $(pwd)/.env:/tmp/.env busybox cp /tmp/.env /config/.env
```

After this, the application is available on port 8000.

## Kör med GitHub Container Registry
Replace the image name with `ghcr.io/OWNER/jk-utbildnings-intyg:latest` in the command above to run your own published image.

## Eller kör med Docker Hub
```bash
docker pull DOCKERHUB_USER/jk-utbildnings-intyg:latest
docker run -d -p 8000:8000 \
  -v env_data:/config \
  -v uploads_data:/app/uploads \
  -v db_data:/data \
  -v logs_data:/app/logs \
  DOCKERHUB_USER/jk-utbildnings-intyg:latest
```

Alternatively, edit `docker-compose.yml` to reference `ghcr.io/OWNER/jk-utbildnings-intyg:latest` or `DOCKERHUB_USER/jk-utbildnings-intyg:latest` as the image and run:

```bash
docker compose up -d
```

