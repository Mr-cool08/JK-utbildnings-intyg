import os

from app import app as application

if __name__ == "__main__":
    # This allows running the app with `python wsgi.py`
    application.run(host="0.0.0.0", port=int(os.getenv("PORT", 80)), debug=bool(os.getenv("DEBUG_MODE", "False")))
