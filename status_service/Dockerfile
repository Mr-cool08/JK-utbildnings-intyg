FROM python:3.15-rc-alpine3.22

WORKDIR /app

COPY status_service/requirements.txt /app/requirements.txt
RUN apk add --no-cache postgresql-dev build-base \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && apk del build-base

COPY status_service /app/status_service
COPY services /app/services
COPY config_loader.py logging_utils.py functions.py /app/

ENV STATUS_PORT=80

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:80", "status_service.app:app"]
