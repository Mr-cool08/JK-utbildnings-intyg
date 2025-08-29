# Deployment

This project ships with a Docker setup and a GitHub Actions workflow that automatically builds a container image and publishes it to the GitHub Container Registry (GHCR).

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

Images are built and pushed to GHCR on every push to the `main` branch. The latest image can be pulled and started as follows (replace `OWNER` with your GitHub username or organisation):

```bash
docker pull ghcr.io/OWNER/jk-utbildnings-intyg:latest

docker run -d --env-file .env -p 8000:8000 ghcr.io/OWNER/jk-utbildnings-intyg:latest
```

This exposes the application on port 8000 and loads environment variables from your local `.env` file. Mount a volume for persistent uploads if needed:

```bash
docker run -d --env-file .env -p 8000:8000 -v $(pwd)/uploads:/app/uploads ghcr.io/OWNER/jk-utbildnings-intyg:latest
```

Alternatively, edit `docker-compose.yml` to reference `ghcr.io/OWNER/jk-utbildnings-intyg:latest` as the image and run:

```bash
docker compose up -d
```

