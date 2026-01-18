# Copyright (c) Liam Suorsa
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clamav \
        clamav-freshclam \
        cron \
        ca-certificates \
        bash \
        msmtp \
        msmtp-mta \
        bsd-mailx \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/clamav /scans /quarantine

COPY run_scan.sh /usr/local/bin/run_scan.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/run_scan.sh /usr/local/bin/entrypoint.sh

VOLUME ["/var/log/clamav", "/scans", "/quarantine"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
