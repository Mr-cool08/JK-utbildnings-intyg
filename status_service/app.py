import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from flask import Flask, Response, render_template, stream_with_context

from functions.notifications import critical_events
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
    project_root = os.getenv(
        "STATUS_PROJECT_ROOT",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
    )

    def generate_output():
        yield "Startar pytest...\n"
        captured_output = []
        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "pytest"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=project_root,
            )
        except (FileNotFoundError, OSError) as exc:
            LOGGER.exception("Kunde inte starta pytest: %s", exc)
            critical_events.send_critical_event_email(
                event_type="error",
                title="🔴 Pytest kunde inte starta",
                description=(
                    "Pytest-körningen kunde inte startas via status-tjänsten.\n"
                    f"Tidsstämpel: {get_display_timestamp()}"
                ),
                error_message=str(exc),
            )
            yield "Pytest kunde inte starta. Kritisk händelse har skickats.\n"
            return
        if process.stdout is None:
            LOGGER.error("Pytest saknar stdout-ström.")
            output, _ = process.communicate()
            if output:
                for line in output.splitlines(keepends=True):
                    captured_output.append(line)
                    yield line
            else:
                captured_output.append("Ingen utdata från pytest.\n")
                yield "Ingen utdata från pytest.\n"
        else:
            for line in process.stdout:
                captured_output.append(line)
                yield line
            process.wait()
        LOGGER.info("Pytest-resultat: %s", process.returncode)
        if process.returncode == 0:
            yield "Pytest klart: lyckades.\n"
        else:
            critical_events.send_critical_event_email(
                event_type="error",
                title="🔴 Pytest misslyckades",
                description=(
                    "Pytest-körningen misslyckades via status-tjänsten.\n"
                    f"Tidsstämpel: {get_display_timestamp()}"
                ),
                error_message="".join(captured_output),
            )
            yield "Pytest misslyckades. Kritisk händelse har skickats.\n"

    return Response(stream_with_context(generate_output()), mimetype="text/plain; charset=utf-8")


    
if __name__ == "__main__":
    port = int(os.getenv("STATUS_PORT", "80"))
    app.run(host="0.0.0.0", port=port)
