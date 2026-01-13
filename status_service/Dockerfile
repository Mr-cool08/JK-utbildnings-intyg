FROM python:3.15-rc-alpine3.22

WORKDIR /app

COPY requirements.txt /app/requirements.txt
COPY status_service/requirements.txt /app/status_service/requirements.txt
RUN apk add --no-cache postgresql-dev build-base \
    && pip install --no-cache-dir -r /app/requirements.txt -r /app/status_service/requirements.txt \
    && apk del build-base

COPY . /app

ENV STATUS_PORT=80

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:80", "status_service.app:app"]
