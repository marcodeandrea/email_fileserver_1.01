# syntax=docker/dockerfile:1.7
FROM python:3.11-slim

# Locale, tz, and non-root user
ENV TZ=America/Argentina/Buenos_Aires         PYTHONDONTWRITEBYTECODE=1         PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends tzdata ca-certificates         && rm -rf /var/lib/apt/lists/*         && adduser --disabled-password --gecos "" appuser

WORKDIR /app
COPY app/ /app/
RUN chmod +x /app/email_file_saver.py && chown -R appuser:appuser /app

# directorio para montar el file server
VOLUME ["/data"]

USER appuser
# Ejecuta en bucle por defecto (POLL_INTERVAL configurable)
ENV POLL_INTERVAL=60 ONE_SHOT=false LOG_LEVEL=INFO DATA_ROOT=/data
ENTRYPOINT [ "python", "/app/email_file_saver.py" ]
