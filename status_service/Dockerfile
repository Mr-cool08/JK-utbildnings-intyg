FROM python:3.11-slim

WORKDIR /app

COPY status_service/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY status_service /app/status_service

ENV STATUS_PORT=80

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:80", "status_service.app:app"]
