# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /root/.local /usr/local
COPY . .
RUN groupadd -r app && useradd -r -g app app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
USER app
ENV PORT=8000
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:$PORT/healthz || exit 1
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
