FROM python:3.12-alpine

WORKDIR /app

RUN apk add --no-cache busybox-suid \
    && addgroup -S failover \
    && adduser -S -D -H -h /app -s /sbin/nologin -G failover failover

COPY scripts/failover /app/scripts/failover

# 👇 Se till att cronfilen heter exakt som usern: failover
RUN if [ -f /app/scripts/failover/crontab ]; then mv /app/scripts/failover/crontab /app/scripts/failover/failover; fi \
    && chmod +x /app/scripts/failover/run_failover_check.sh \
    && chown -R failover:failover /app/scripts/failover

USER failover

CMD ["crond", "-f", "-d", "8", "-c", "/app/scripts/failover"]

# Copyright (c) Liam Suorsa and Mika Suorsa
