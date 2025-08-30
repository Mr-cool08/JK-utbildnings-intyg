# Use official Python runtime as a parent image
FROM python:3.11-slim

# Set work directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Ensure runtime directories exist, seed configuration volume
RUN mkdir -p /data /app/uploads /config \
    && cp .example.env /config/.env
VOLUME ["/data", "/app/uploads", "/config"]

# Configure port and default database location
ENV PORT=80 \
    DB_PATH=/data/database.db \
    PYTHONUNBUFFERED=1

EXPOSE 80

# Run the application with Gunicorn
CMD ["gunicorn", "app:app", "--workers=3", "--bind=0.0.0.0:${PORT}", \
     "--access-logfile=-", "--error-logfile=-", "--log-level=info", "--capture-output"]
