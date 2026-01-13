import logging
import os
import subprocess
from datetime import datetime, timezone
from flask import Flask, Response, render_template, stream_with_context

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


@app.route("/pytest")
def pytest_site():
    LOGGER.info("Startar pytest-körning via status-tjänsten.")

    def generate_output():
        yield "Startar pytest...\n"
        process = subprocess.Popen(
            ["pytest"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in process.stdout:
            yield line
        process.wait()
        LOGGER.info("Pytest-resultat: %s", process.returncode)
        if process.returncode == 0:
            yield "Pytest klart: lyckades.\n"
        else:
            yield f"Pytest klart: misslyckades ({process.returncode}).\n"

    return Response(stream_with_context(generate_output()), mimetype="text/plain; charset=utf-8")


    
if __name__ == "__main__":
    port = int(os.getenv("STATUS_PORT", "80"))
    app.run(host="0.0.0.0", port=port)
