import os
from app import app as application
debug = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "yes")


if __name__ == "__main__":
    # This allows running the app with `python wsgi.py`
    application.run(
    host="0.0.0.0",
    port=int(os.getenv("PORT", 80)),
    debug=debug
)
