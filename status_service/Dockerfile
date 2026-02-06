# Copyright (c) Liam Suorsa
FROM python:3.13-alpine3.21

WORKDIR /app

COPY status_service/requirements.txt /app/requirements.txt

# Viktigt: uppdatera/uppgradera baspaket så openssl blir patchad
RUN apk update \
    && apk upgrade --no-cache \
    && apk add --no-cache \
        openssl \
        postgresql-dev build-base \
        zlib zlib-dev \
        libffi libffi-dev \
        libjpeg-turbo-dev \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && apk del build-base zlib-dev libffi-dev

COPY status_service /app/status_service

ENV STATUS_PORT=80

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:80", "status_service.app:app"]
