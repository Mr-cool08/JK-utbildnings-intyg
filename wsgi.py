# Copyright (c) Liam Suorsa and Mika Suorsa
import os

from app import app as application
from functions.requests import as_bool

# Expose ``app`` for servers expecting this name (e.g., gunicorn's ``wsgi:app``).
# HTTPS/TLS termination is handled by Cloudflare at the edge; cloudflared forwards HTTP internally.
app = application

debug = as_bool(os.getenv("DEV_MODE"))

if __name__ == "__main__":
    # Local and direct WSGI runs speak HTTP; public HTTPS terminates at Cloudflare.
    application.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 80)),
        debug=debug,
    )
