FROM python:3.12-alpine

WORKDIR /app

RUN apk add --no-cache busybox-suid

COPY scripts/failover /app/scripts/failover

RUN chmod +x /app/scripts/failover/run_failover_check.sh

CMD ["crond", "-f", "-l", "2", "-c", "/app/scripts/failover"]

# Copyright (c) Liam Suorsa and Mika Suorsa
