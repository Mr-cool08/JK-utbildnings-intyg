FROM python:3.12-alpine

WORKDIR /app

RUN apk add --no-cache busybox-suid \
    && addgroup -S failover \
    && adduser -S -D -H -h /app -s /sbin/nologin -G failover failover

COPY scripts/failover /app/scripts/failover

RUN chmod +x /app/scripts/failover/run_failover_check.sh \
    && chown -R failover:failover /app/scripts/failover

USER failover

CMD ["crond", "-f", "-l", "2", "-c", "/app/scripts/failover"]

# Copyright (c) Liam Suorsa and Mika Suorsa
