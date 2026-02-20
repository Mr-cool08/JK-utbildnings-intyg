# Copyright (c) Liam Suorsa
import os
from datetime import datetime
from zoneinfo import ZoneInfo
from flask import Flask, render_template

from functions.logging import bootstrap_logging
from status_service.status_checks import build_status

app = Flask(__name__)
LOGGER = bootstrap_logging(__name__, level_env_vars=("STATUS_LOG_LEVEL", "LOG_LEVEL"))


def get_display_timestamp():
    timezone_name = os.getenv("APP_TIMEZONE", "Europe/Stockholm")
    now = datetime.now(ZoneInfo(timezone_name))
    return now.strftime("%Y-%m-%d %H:%M:%S %Z")


@app.route("/")
def index():
    status = build_status()
    LOGGER.info(
        "Statuskontroll klar. SSL: %s, Databas: %s, Traefik: %s.",
        status["checks"]["ssl"]["status"],
        status["checks"]["database"]["status"],
        status["checks"]["traefik"]["status"],
    )
    return render_template("status.html", status=status, checked_at=get_display_timestamp())


if __name__ == "__main__":
    port = int(os.getenv("STATUS_PORT", "80"))
    app.run(host="0.0.0.0", port=port)
