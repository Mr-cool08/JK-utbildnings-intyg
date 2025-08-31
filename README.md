# JK Utbildningsintyg

This web application manages the issuance and storage of course certificates. It separates responsibilities between administrators and end users so each party can focus on their own tasks.

## Getting started

1. **Install dependencies**
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Configure environment variables** – copy `.example.env` to `.env` and update the values to match your setup.
3. **Run the application**
   ```bash
   python app.py
   ```
   The app will be available on <http://localhost:80>. For container-based deployment see [DEPLOYMENT.md](DEPLOYMENT.md).

### Optional: Cloudflare TLS support

If you are using [Cloudflare Origin Certificates](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/),
provide the certificate and key paths via the ``CLOUDFLARE_CERT_PATH`` and
``CLOUDFLARE_KEY_PATH`` environment variables. When both are set the
application will start with TLS enabled using those files. For the Docker
setup, place the certificate and key in the `client_52_3` home directory (for
example `/home/client_52_3/certs/`) and mount that directory at the same path
inside the container. Point the variables to those files (e.g.
`/home/client_52_3/certs/cert.pem` and `/home/client_52_3/certs/key.pem`).

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

* **SQLite database** – User metadata and pending registrations are stored in a local SQLite database file.
* **File system** – Certificates reside in an `uploads/<personnummer>/` directory structure. The application only accepts PDF files to prevent accidental uploads of other formats.
* **Hashed credentials** – Passwords are hashed with a per-user salt using PBKDF2 via Werkzeug, while personal numbers and emails are deterministically hashed with a global salt so sensitive data isn't stored in plain text.

## Persistent data with Docker

Running the application with Docker Compose stores mutable data in named volumes so that updates to the container image do not remove important files:

* `env_data` – contains the `.env` configuration file mounted at `/config/.env` inside the container.
* `uploads_data` – keeps user uploads available at `/app/uploads`.
* `db_data` – persists the SQLite database in `/data/database.db`.
* `logs_data` – retains application logs under `/app/logs/`.
These volumes have fixed names so existing data is reused across container rebuilds.

Cloudflare certificates are stored outside of Docker volumes in
`/home/client_52_3/certs` and mounted to `/home/client_52_3/certs` in the
container.

Ensure the `env_data` volume includes a valid `.env` file before starting the container to provide required configuration values.

## Running tests

```bash
pytest
```

