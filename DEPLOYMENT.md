# Deployment

This project ships with a Docker setup and a GitHub Actions workflow that automatically builds a container image and publishes it to the GitHub Container Registry (GHCR) and Docker Hub.

## Prerequisites

- Docker or Docker Desktop installed

## Local development

You can build and run the container locally with Docker Compose:

```bash
docker compose up --build
```

The app will be available on http://localhost:8000.

## Production deployment

Images are built and pushed to GHCR and Docker Hub on every push to the `main` branch. Run the latest image as follows:

```bash
docker pull ghcr.io/mr-cool08/jk-utbildnings-intyg:latest

docker run -d -p 8000:8000 \
  -v env_data:/config \
  -v uploads_data:/app/uploads \
  -v db_data:/data \
  -v logs_data:/app/logs \
  ghcr.io/mr-cool08/jk-utbildnings-intyg:latest
```

The volumes are created automatically if they do not exist. On first start the container copies `.example.env` into the `env_data` volume as `.env`. Edit this file and restart the container to update environment variables.

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
