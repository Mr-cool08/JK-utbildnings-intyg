# JK Utbildningsintyg

This web application manages the issuance and storage of course certificates. It separates responsibilities between administrators and end users so each party can focus on their own tasks.

## Getting started

1. **Install dependencies**
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Configure environment variables** – copy `.example.env` to `.env` and update the values to match your setup. Set `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD`; when the container starts it automatically launches an internal PostgreSQL server with those credentials whenever `DATABASE_URL` is empty (`BUNDLED_POSTGRES=auto`). For Docker Compose the same values are passed to the dedicated `db` service. If you already operate a PostgreSQL server elsewhere, set `POSTGRES_HOST` (and optionally override `POSTGRES_PORT`) while leaving `DATABASE_URL` empty—the application constructs the connection string from those values and skips the bundled instance. Alternatively set `DATABASE_URL` explicitly. Switch the bundled server off with `BUNDLED_POSTGRES=off` when relying on an external database; without any PostgreSQL configuration the application falls back to the SQLite database referenced by `DB_PATH`.
3. **Run the application**
   ```bash
   python app.py
   ```
   The app will be available on <http://localhost:80>. For container-based deployment see [DEPLOYMENT.md](DEPLOYMENT.md).

### Optional: custom TLS certificates

The container generates a self-signed certificate automatically so HTTPS works
out of the box. To use your own certificate, provide the PEM-encoded
certificate and key via the ``TLS_CERT`` and ``TLS_KEY`` environment
variables in your `.env` file. When both are present their contents are written
to `/etc/nginx/certs/server.crt` and `/etc/nginx/certs/server.key` inside the
container.


## How it works for administrators

* **Login** – Administrators sign in with credentials configured by the owner. A valid session grants access to the admin panel.
* **Register pending users** – Through the admin panel an administrator submits a learner’s email, username and Swedish personal number together with a PDF certificate. The system normalises the personal number and stores the certificate in a folder named after that number.
* **Database entry** – If the learner is not yet active, an entry is created in the `pending_users` table pointing to the uploaded PDF. Should the learner already exist, only the PDF is added to their folder.
* **Security checks** – Uploaded files are verified to be genuine PDFs before storage. Each file receives a timestamped name to avoid collisions.

## How it works for users

* **Account activation** – After an administrator registers them, the learner visits a personalised account creation link and sets a password. The pending entry is moved into the `users` table.
* **Login and dashboard** – Users sign in with their personal number and password. A successful login opens a dashboard listing all PDF certificates stored for that personal number.
* **Downloading certificates** – Each listed PDF links to a direct download route so the learner can retrieve their documents whenever needed.
* **Session management** – Logging out clears the session for both user and admin roles, ensuring access is protected.

## Data storage

* **Bundled PostgreSQL (container deployments)** – When the container runs with `BUNDLED_POSTGRES=auto` (default) or `always`, the entrypoint starts an internal PostgreSQL server and stores its data under `/var/lib/postgresql/data`. Mount this path to a named or bind volume to persist the database across rebuilds.
* **SQLite database** – For local development or when `BUNDLED_POSTGRES=off`, the application stores user metadata and pending registrations in a local SQLite database file instead.
* **File system** – Certificates reside in an `uploads/<personnummer>/` directory structure. The application only accepts PDF files to prevent accidental uploads of other formats.
* **Hashed credentials** – Passwords are hashed with a per-user salt using PBKDF2 via Werkzeug, while personal numbers and emails are deterministically hashed with a global salt so sensitive data isn't stored in plain text.

## Persistent data with Docker

Running the application with Docker Compose stores mutable data in named volumes so that updates to the container image do not remove important files:

* `postgres_data` – stores the data directory for the Docker Compose managed PostgreSQL instance.
* `postgres_internal_data` – persists the bundled PostgreSQL server that runs inside the application container when `BUNDLED_POSTGRES` is enabled.
* `env_data` – contains the `.env` configuration file mounted at `/config/.env` inside the container.
* `uploads_data` – keeps user uploads available at `/app/uploads`.
* `db_data` – persists the SQLite fallback in `/data/database.db` when `BUNDLED_POSTGRES=off`.
* `logs_data` – retains application logs under `/app/logs/`.
These volumes have fixed names so existing data is reused across container rebuilds.

Ensure the `env_data` volume includes a valid `.env` file before starting the container to provide required configuration values. The container now starts an internal PostgreSQL server automatically when `DATABASE_URL` is empty, so remember to mount `/var/lib/postgresql/data` (for example with the `postgres_internal_data` volume) if you want the database to persist.

If you prefer running a separate PostgreSQL container without Docker Compose,
execute `./scripts/start_postgres_stack.sh`. The script reads `POSTGRES_*`
values from your `.env` file, spins up a matching PostgreSQL container, and
launches the application container with `DATABASE_URL` pointing at that
database.

## Running tests

```bash
pytest
```

