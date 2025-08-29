# Use official Python runtime as a parent image
FROM python:3.11-slim

# Set work directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Ensure runtime directories exist and declare them as volumes for persistence
RUN mkdir -p /data /app/uploads /app/logs /config
VOLUME ["/data", "/app/uploads", "/app/logs", "/config"]

# Configure port and default database location
ENV PORT=8000 \
    DB_PATH=/data/database.db
EXPOSE 8000

# Run the application with Gunicorn
CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${PORT} wsgi:application"]
