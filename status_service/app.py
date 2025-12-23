import logging
import os
from datetime import datetime, timezone

from flask import Flask, render_template

from status_service.status_checks import build_status

app = Flask(__name__)
logging.basicConfig(level=os.getenv("STATUS_LOG_LEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)


def get_display_timestamp():
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%d %H:%M:%S UTC")


@app.route("/")
def index():
    status = build_status()
    LOGGER.info(
        "Statuskontroll klar. SSL: %s, Databas: %s, Nginx: %s.",
        status["checks"]["ssl"]["status"],
        status["checks"]["database"]["status"],
        status["checks"]["nginx"]["status"],
    )
    return render_template("status.html", status=status, checked_at=get_display_timestamp())


if __name__ == "__main__":
    port = int(os.getenv("STATUS_PORT", "80"))
    app.run(host="0.0.0.0", port=port)
