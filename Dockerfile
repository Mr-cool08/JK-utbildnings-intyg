FROM python:3.12-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
COPY --from=build /usr/local /usr/local
COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends curl \ 
    && rm -rf /var/lib/apt/lists/* && \
    useradd -m appuser && chown -R appuser:appuser /app
USER appuser
HEALTHCHECK CMD curl -f http://localhost:${PORT:-8000}/healthz || exit 1
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
