# JK Utbildningsintyg

This web application manages the issuance and storage of course certificates. It separates responsibilities between administrators and end users so each party can focus on their own tasks.

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

This description focuses on the internal workflow and division of responsibilities. Operational details such as installation or deployment are intentionally omitted.

