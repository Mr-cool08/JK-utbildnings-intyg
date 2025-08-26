# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
COPY --from=build /usr/local /usr/local
COPY . .
RUN useradd -m appuser && \
    apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
USER appuser
ENV PORT=8000
HEALTHCHECK CMD curl -f http://localhost:$PORT/healthz || exit 1
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
