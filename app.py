 # Flask application for issuing and serving course certificates.

from __future__ import annotations

import logging
import os
import ssl
import time
from datetime import datetime, timezone
from typing import Sequence
from email import policy
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from smtplib import (
    SMTP,
    SMTPAuthenticationError,
    SMTPException,
    SMTPServerDisconnected,
    SMTP_SSL,
)

from flask import (
    Flask,
    abort,
    current_app,
    jsonify,
    send_from_directory,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from config_loader import load_environment
from logging_utils import configure_module_logger

from course_categories import (
    COURSE_CATEGORIES,
    labels_for_slugs,
    normalize_category_slugs,
)


load_environment()

import functions

ALLOWED_MIMES = {'application/pdf'}

logger = configure_module_logger(__name__)
logger.setLevel(logging.INFO)
# functions.create_test_user()  # Skapa en testanvändare vid start




def _enable_debug_mode(app: Flask) -> None:
    # Aktivera extra loggning och ev. testdata i debug-läge.
    stream = logging.StreamHandler()
    root = logging.getLogger()
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        root.addHandler(stream)
    root.setLevel(logging.DEBUG)

    if not any(isinstance(h, logging.StreamHandler) for h in app.logger.handlers):
        app.logger.addHandler(stream)
    app.logger.setLevel(logging.DEBUG)

    functions.logger.setLevel(logging.DEBUG)
    if not any(isinstance(h, logging.StreamHandler) for h in functions.logger.handlers):
        functions.logger.addHandler(stream)

    functions.logger.debug("Debug mode is on")
    logger.debug("Debug mode is on")
    # Skapa testanvändare endast i debug-läge
    functions.create_test_user()
    print("Debug mode is on, test user created")



def create_app() -> Flask:
    # Create and configure the Flask application.
    logger.debug("Loading environment variables and initializing database")
    functions.create_database()
    app = Flask(__name__)
    app.secret_key = os.getenv('secret_key')
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

    with app.app_context():
        if app.debug:
            _enable_debug_mode(app)

    logger.debug("Application created and database initialized")
    return app


app = create_app()


@app.route("/health")
def health() -> tuple[dict, int]:
    # Basic health check endpoint.
    return {"status": "ok"}, 200

def send_creation_email(to_email: str, link: str) -> None:
    # Send a password creation link via SMTP.

    # Uses STARTTLS for port 587 and connects with SSL when port 465 is specified.
    
    normalized_email = functions.normalize_email(to_email)
    if normalized_email != to_email:
        logger.debug(
            "Normalized recipient email from %r to %s", to_email, normalized_email
        )

    smtp_server = os.getenv("smtp_server")
    smtp_port = int(os.getenv("smtp_port", "587"))
    smtp_user = os.getenv("smtp_user")
    smtp_password = os.getenv("smtp_password")
    smtp_timeout = int(os.getenv("smtp_timeout", "10"))

    if not (smtp_server and smtp_user and smtp_password):
        raise RuntimeError("Saknar env: smtp_server, smtp_user eller smtp_password")

    msg = EmailMessage(policy=policy.SMTP.clone(max_line_length=1000))
    msg["Subject"] = "Skapa ditt konto"
    msg["From"] = smtp_user
    msg["To"] = normalized_email
    msg["Message-ID"] = make_msgid()
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg.set_content(
        f"""
        <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.5;'>
                <p>Hej,</p>
                <p>Skapa ditt konto genom att besöka denna länk:</p>
                <p><a href="{link}">{link}</a></p>
                <p>Om du inte begärde detta e-postmeddelande kan du ignorera det.</p>
            </body>
        </html>
        """,
        subtype="html",
    )

    context = ssl.create_default_context()

    try:
        use_ssl = smtp_port == 465
        logger.info(
            "Förbereder utskick till %s via %s:%s (%s, timeout %ss)",
            normalized_email,
            smtp_server,
            smtp_port,
            "SSL" if use_ssl else "STARTTLS",
            smtp_timeout,
        )

        smtp_cls = SMTP_SSL if use_ssl else SMTP
        smtp_kwargs = {"timeout": smtp_timeout}
        if use_ssl:
            smtp_kwargs["context"] = context

        with smtp_cls(smtp_server, smtp_port, **smtp_kwargs) as smtp:
            if hasattr(smtp, "ehlo"):
                smtp.ehlo()

            if not use_ssl:
                try:
                    from inspect import signature

                    if "context" in signature(smtp.starttls).parameters:
                        smtp.starttls(context=context)
                        logger.debug("SMTP STARTTLS initierad med kontext")
                    else:
                        smtp.starttls()
                        logger.debug("SMTP STARTTLS initierad utan kontext")
                except (TypeError, ValueError):
                    smtp.starttls()
                    logger.debug("SMTP STARTTLS initierad (fallback)")

                if hasattr(smtp, "ehlo"):
                    smtp.ehlo()

            smtp.login(smtp_user, smtp_password)
            logger.debug("SMTP inloggning lyckades för %s", smtp_user)

            if hasattr(smtp, "send_message"):
                refused = smtp.send_message(msg)
            else:
                refused = smtp.sendmail(
                    smtp_user, [normalized_email], msg.as_string()
                )

            if refused:
                logger.error("SMTP server refused recipients: %s", refused)
                raise RuntimeError("E-postservern accepterade inte mottagaren.")

        logger.info("Skickade aktiveringslänk till %s", normalized_email)
        logger.debug(
            "Meddelande-ID för utskick till %s: %s",
            normalized_email,
            msg["Message-ID"],
        )

    except SMTPAuthenticationError as exc:
        logger.exception("SMTP login failed for %s", smtp_user)
        raise RuntimeError("SMTP-inloggning misslyckades") from exc
    except SMTPServerDisconnected as exc:
        logger.exception("Server closed the connection during SMTP session")
        raise RuntimeError("Det gick inte att skicka e-post") from exc
    except SMTPException as exc:
        logger.exception("SMTP error when sending to %s", normalized_email)
        raise RuntimeError("Det gick inte att skicka e-post") from exc
    except OSError as exc:
        logger.exception("Connection error to email server")
        raise RuntimeError("Det gick inte att ansluta till e-postservern") from exc


def _require_admin() -> str:
    if not session.get("admin_logged_in"):
        abort(403)
    return session.get("admin_username", "okänd")

def send_password_reset_email(to_email: str, link: str) -> None:
    # Skicka e-post med länk för återställning av lösenord.
    normalized_email = functions.normalize_email(to_email)
    smtp_server = os.getenv("smtp_server")
    smtp_port = int(os.getenv("smtp_port", "587"))
    smtp_user = os.getenv("smtp_user")
    smtp_password = os.getenv("smtp_password")
    smtp_timeout = int(os.getenv("smtp_timeout", "10"))

    if not (smtp_server and smtp_user and smtp_password):
        raise RuntimeError("Saknar env: smtp_server, smtp_user eller smtp_password")

    msg = EmailMessage(policy=policy.SMTP.clone(max_line_length=1000))
    msg["Subject"] = "Återställ ditt lösenord"
    msg["From"] = smtp_user
    msg["To"] = normalized_email
    msg["Message-ID"] = make_msgid()
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg.set_content(
        f"""
        <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.5;'>
                <p>Hej,</p>
                <p>Du har begärt att återställa ditt lösenord. Använd länken nedan för att välja ett nytt lösenord:</p>
                <p><a href="{link}">{link}</a></p>
                <p>Länken är giltig i 48 timmar. Om du inte begärde detta kan du ignorera meddelandet.</p>
            </body>
        </html>
        """,
        subtype="html",
    )

    context = ssl.create_default_context()

    try:
        use_ssl = smtp_port == 465
        smtp_cls = SMTP_SSL if use_ssl else SMTP
        smtp_kwargs = {"timeout": smtp_timeout}
        if use_ssl:
            smtp_kwargs["context"] = context

        with smtp_cls(smtp_server, smtp_port, **smtp_kwargs) as smtp:
            if hasattr(smtp, "ehlo"):
                smtp.ehlo()

            if not use_ssl:
                try:
                    from inspect import signature

                    if "context" in signature(smtp.starttls).parameters:
                        smtp.starttls(context=context)
                    else:
                        smtp.starttls()
                except (TypeError, ValueError):
                    smtp.starttls()

                if hasattr(smtp, "ehlo"):
                    smtp.ehlo()

            smtp.login(smtp_user, smtp_password)

            if hasattr(smtp, "send_message"):
                refused = smtp.send_message(msg)
            else:
                refused = smtp.sendmail(
                    smtp_user,
                    [normalized_email],
                    msg.as_string(),
                )

            if refused:
                logger.error("SMTP server refused recipients: %s", refused)
                raise RuntimeError("E-postservern accepterade inte mottagaren.")

    except (SMTPAuthenticationError, SMTPServerDisconnected, SMTPException) as exc:
        logger.exception("SMTP-fel vid utskick av återställningsmejl")
        raise RuntimeError("Det gick inte att skicka återställningsmejlet.") from exc

@app.context_processor
def inject_flags():
    # Expose flags indicating debug mode to Jinja templates.
    # return {"IS_DEV": current_app.debug}  # funkar också
    return {"IS_DEV": app.debug}



def save_pdf_for_user(
    pnr: str, file_storage, categories: Sequence[str]
) -> dict[str, str | int | Sequence[str]]:
    # Validate and store a PDF in the database for the provided personnummer.
    logger.debug("Saving PDF for personnummer %s", pnr)
    if file_storage.filename == "":
        logger.error("No file selected for upload")
        raise ValueError("Ingen fil vald.")

    mime = file_storage.mimetype or ""
    if mime not in ALLOWED_MIMES:
        logger.error("Disallowed MIME type %s", mime)
        raise ValueError("Endast PDF tillåts.")

    head = file_storage.stream.read(5)
    file_storage.stream.seek(0)
    if head != b"%PDF-":
        logger.error("File does not appear to be valid PDF")
        raise ValueError("Filen verkar inte vara en giltig PDF.")

    selected_categories = normalize_category_slugs(categories)
    if len(selected_categories) != 1:
        logger.error(
            "Invalid number of categories (%d) for %s",
            len(selected_categories),
            pnr,
        )
        raise ValueError("Exakt en kurskategori måste väljas.")

    pnr_norm = functions.normalize_personnummer(pnr)
    pnr_hash = functions.hash_value(pnr_norm)

    base = secure_filename(file_storage.filename)
    base = base.replace(pnr_norm, "")
    base = base.lstrip("_- ")
    if not base:
        base = "certificate.pdf"
    # lägg på timestamp för att undvika krockar
    filename = f"{int(time.time())}_{base}"

    file_storage.stream.seek(0)
    content = file_storage.stream.read()
    pdf_id = functions.store_pdf_blob(pnr_hash, filename, content, selected_categories)
    logger.info("Stored PDF for %s as id %s", pnr, pdf_id)
    return {"id": pdf_id, "filename": filename, "categories": selected_categories}

@app.route('/robots.txt')
def robots_txt():
    # Serve robots.txt to disallow all crawlers.
    return send_from_directory(app.static_folder, 'robots.txt', mimetype='text/plain')

@app.route('/create_user/<pnr_hash>', methods=['POST', 'GET'])
def create_user(pnr_hash):
    # Allow a pending user to set a password and activate the account.
    logger.info("Handling create_user for hash %s", pnr_hash)
    if request.method == 'POST':
        password = request.form['password']
        logger.debug("Creating user with hash %s", pnr_hash)
        functions.user_create_user(password, pnr_hash)
        return redirect('/login')
    elif request.method == 'GET':
        if functions.check_pending_user_hash(pnr_hash):
            return render_template('create_user.html')
        else:
            logger.warning("User hash %s not found during create_user", pnr_hash)
            return "Fel: Användaren hittades inte"


@app.route('/aterstall-losenord/<token>', methods=['GET', 'POST'])
def password_reset(token: str):
    info = functions.get_password_reset(token)
    if not info or info.get('used_at') is not None:
        return render_template('password_reset.html', invalid=True)

    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm = request.form.get('confirm', '').strip()
        if not password or password != confirm:
            return render_template(
                'password_reset.html',
                invalid=False,
                error='Lösenorden måste fyllas i och matcha.',
            )
        if len(password) < 8:
            return render_template(
                'password_reset.html',
                invalid=False,
                error='Lösenordet måste vara minst 8 tecken.',
            )
        if not functions.reset_password_with_token(token, password):
            return render_template('password_reset.html', invalid=True)
        return redirect('/login')

    return render_template('password_reset.html', invalid=False)

@app.route('/', methods=['GET'])
def home():
    # Render the landing page.
    logger.debug("Rendering home page")
    return render_template('index.html')



@app.route('/license', methods=['GET'])
def license():
    # Render the license information page.
    logger.debug("Rendering license page")
    return render_template('license.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Authenticate users using personnummer and password.
    if request.method == 'POST':
        personnummer = request.form['personnummer']
        personnummer = functions.normalize_personnummer(personnummer)
        if personnummer == "" or not personnummer.isnumeric():
            logger.error("Invalid personnummer: %s", personnummer)
            return (
                render_template('user_login.html', error='Ogiltiga inloggningsuppgifter'),
                401,
            )
        password = request.form['password']
        if password == "":
            logger.error("Empty password provided for %s", personnummer)
            return (
                render_template('user_login.html', error='Ogiltiga inloggningsuppgifter'),
                401,
            )
        logger.debug("Login attempt for %s", personnummer)
        if functions.check_personnummer_password(personnummer, password):
            session['user_logged_in'] = True
            personnummer_hash = functions.hash_value(personnummer)
            session['personnummer'] = personnummer_hash
            session['username'] = functions.get_username_by_personnummer_hash(
                personnummer_hash
            )
            logger.info("User %s logged in", personnummer)
            return redirect('/dashboard')
        else:
            logger.warning("Invalid login for %s", personnummer)
            return (
                render_template('user_login.html', error='Ogiltiga inloggningsuppgifter'),
                401,
            )
    logger.debug("Rendering login page")
    return render_template('user_login.html')


@app.route('/dashboard', methods=['GET'])
def dashboard():
    # Visa alla PDF:er för den inloggade användaren.
    if not session.get('user_logged_in'):
        logger.debug("Unauthenticated access to dashboard")
        return redirect('/login')
    pnr_hash = session.get('personnummer')
    user_name = session.get('username')
    if not user_name and pnr_hash:
        user_name = functions.get_username_by_personnummer_hash(pnr_hash)
        if user_name:
            session['username'] = user_name
    pdfs = functions.get_user_pdfs(pnr_hash)
    for pdf in pdfs:
        pdf["category_labels"] = labels_for_slugs(pdf.get("categories", []))
    grouped_pdfs = []
    groups_by_slug = {}
    for slug, label in COURSE_CATEGORIES:
        group = {"slug": slug, "label": label, "pdfs": []}
        grouped_pdfs.append(group)
        groups_by_slug[slug] = group
    uncategorized_group = {
        "slug": "okategoriserade",
        "label": "Okategoriserade intyg",
        "pdfs": [],
    }
    for pdf in pdfs:
        categories = pdf.get("categories") or []
        matched = False
        for slug in categories:
            group = groups_by_slug.get(slug)
            if group is not None:
                group["pdfs"].append(pdf)
                matched = True
        if not matched:
            uncategorized_group["pdfs"].append(pdf)
    visible_groups = [group for group in grouped_pdfs if group["pdfs"]]
    if uncategorized_group["pdfs"]:
        visible_groups.append(uncategorized_group)
    category_summary = [
        {
            "slug": slug,
            "label": label,
            "count": len(groups_by_slug[slug]["pdfs"]),
        }
        for slug, label in COURSE_CATEGORIES
    ]
    if uncategorized_group["pdfs"]:
        category_summary.append(
            {
                "slug": uncategorized_group["slug"],
                "label": uncategorized_group["label"],
                "count": len(uncategorized_group["pdfs"]),
            }
        )
    logger.debug("Dashboard for %s shows %d pdfs", pnr_hash, len(pdfs))
    user_name = user_name.capitalize()
    return render_template(
        'dashboard.html',
        pdfs=pdfs,
        course_categories=COURSE_CATEGORIES,
        category_summary=category_summary,
        grouped_pdfs=visible_groups,
        user_name=user_name,
    )


@app.route('/my_pdfs/<int:pdf_id>')
def download_pdf(pdf_id: int):
    # Serve a stored PDF for the logged-in user from the database.
    if not session.get('user_logged_in'):
        logger.debug("Unauthenticated download attempt for %s", pdf_id)
        return redirect('/login')
    pnr_hash = session.get('personnummer')
    as_attachment = request.args.get('download', '1') != '0'
    pdf = functions.get_pdf_content(pnr_hash, pdf_id)
    if not pdf:
        logger.warning("PDF %s not found for user %s", pdf_id, pnr_hash)
        abort(404)
    filename, content = pdf
    logger.info(
        "User %s retrieving %s (as_attachment=%s)", pnr_hash, filename, as_attachment
    )
    response = make_response(content)
    response.headers['Content-Type'] = 'application/pdf'
    disposition = 'attachment' if as_attachment else 'inline'
    response.headers['Content-Disposition'] = f"{disposition}; filename=\"{filename}\""
    return response


@app.route('/view_pdf/<int:pdf_id>')
def view_pdf(pdf_id: int):
    # Redirect to a direct download of the specified PDF.
    if not session.get('user_logged_in'):
        logger.debug("Unauthenticated view attempt for %s", pdf_id)
        return redirect('/login')
    pnr_hash = session.get('personnummer')
    pdf = functions.get_pdf_metadata(pnr_hash, pdf_id)
    if not pdf:
        logger.warning("PDF %s not found for user %s", pdf_id, pnr_hash)
        abort(404)
    logger.info("User %s laddar ned %s via direktlänk", pnr_hash, pdf['filename'])
    return redirect(url_for('download_pdf', pdf_id=pdf_id))

@app.route('/admin', methods=['POST', 'GET'])
def admin():
    # Admin dashboard for uploading certificates and creating users.
    if request.method == 'POST':
        if not session.get('admin_logged_in'):
            logger.warning("Unauthorized admin POST")
            return redirect('/login_admin')

        try:
            # --- Grab form data ---
            email = request.form.get('email', '').strip()
            username = request.form.get('username', '').strip()
            personnummer = functions.normalize_personnummer(request.form.get('personnummer', '').strip())

            raw_categories = request.form.getlist('categories')
            pdf_files = request.files.getlist('pdf')
            if not raw_categories:
                logger.warning("Admin upload missing categories (no selection)")
                return jsonify({'status': 'error', 'message': 'Välj kategori för varje PDF.'}), 400
            if not pdf_files:
                logger.warning("Admin upload without PDF")
                return jsonify({'status': 'error', 'message': 'PDF-fil saknas'}), 400

            if len(raw_categories) != len(pdf_files):
                logger.warning(
                    "Admin upload category mismatch (categories=%d, files=%d)",
                    len(raw_categories),
                    len(pdf_files),
                )
                return jsonify({'status': 'error', 'message': 'Välj kategori för varje PDF.'}), 400

            logger.debug(
                "Admin upload for %s with categories %s",
                personnummer,
                raw_categories,
            )

            normalized_categories = []
            for idx, raw in enumerate(raw_categories):
                selected = normalize_category_slugs([raw])
                if len(selected) != 1:
                    logger.warning(
                        "Admin upload invalid category for file %d (value=%r)",
                        idx,
                        raw,
                    )
                    return jsonify({'status': 'error', 'message': 'Välj giltig kategori för varje PDF.'}), 400
                normalized_categories.append(selected[0])

            # --- Check if user exists ---
            user_exists = functions.get_user_info(personnummer) or functions.check_user_exists(email)
            pnr_hash = functions.hash_value(personnummer)
            pending_exists = functions.check_pending_user_hash(pnr_hash)

            # --- Save PDFs ---
            pdf_records = [
                save_pdf_for_user(personnummer, file_storage, [category])
                for file_storage, category in zip(pdf_files, normalized_categories)
            ]

            # --- Return early for existing or pending users ---
            if user_exists:
                logger.info("PDFs uploaded for existing user %s (%d files)", personnummer, len(pdf_records))
                return jsonify({'status': 'success', 'message': 'PDF:er uppladdade för befintlig användare'})

            if pending_exists:
                logger.info("PDFs uploaded for pending user %s (%d files)", personnummer, len(pdf_records))
                return jsonify({'status': 'success', 'message': 'Användaren väntar redan på aktivering. PDF:er uppladdade.'})

            # --- Create new pending user ---
            if functions.admin_create_user(email, username, personnummer):
                link = url_for('create_user', pnr_hash=pnr_hash, _external=True)
                try:
                    send_creation_email(email, link)
                except RuntimeError as e:
                    logger.error("Failed to send creation email to %s", email)
                    return jsonify({'status': 'error', 'message': str(e)}), 500

                logger.info("Admin created user %s", personnummer)
                return jsonify({'status': 'success', 'message': 'Användare skapad', 'link': link})

            logger.error("Failed to create pending user for %s", personnummer)
            return jsonify({'status': 'error', 'message': 'Kunde inte skapa användare'}), 500

        except ValueError as ve:
            logger.error("Value error during admin upload: %s", ve)
            return jsonify({'status': 'error', 'message': 'Felaktiga användardata.'}), 400
        except Exception as e:
            logger.exception("Server error during admin upload")
            return jsonify({'status': 'error', 'message': 'Serverfel'}), 500

    # --- GET request ---
    if not session.get('admin_logged_in'):
        logger.warning("Unauthorized admin GET")
        return redirect('/login_admin')

    logger.debug("Rendering admin page")
    return render_template(
        'admin.html',
        categories=COURSE_CATEGORIES,
    )


@app.post('/admin/api/oversikt')
def admin_user_overview():
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get('personnummer') or '').strip()
    if not personnummer:
        return jsonify({'status': 'error', 'message': 'Ange personnummer.'}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Ogiltigt personnummer.'}), 400

    pnr_hash = functions.hash_value(normalized_personnummer)
    pdfs = functions.get_user_pdfs(pnr_hash)
    overview = []
    for pdf in pdfs:
        overview.append(
            {
                'id': pdf['id'],
                'filename': pdf['filename'],
                'categories': pdf.get('categories') or [],
                'category_labels': labels_for_slugs(pdf.get('categories') or []),
                'uploaded_at': pdf.get('uploaded_at').isoformat()
                if pdf.get('uploaded_at')
                else None,
            }
        )

    user_row = functions.get_user_info(normalized_personnummer)
    pending = functions.check_pending_user(normalized_personnummer)
    response = {
        'status': 'success',
        'data': {
            'personnummer_hash': pnr_hash,
            'username': user_row.username if user_row else None,
            'email_hash': user_row.email if user_row else None,
            'pending': pending,
            'pdfs': overview,
            'categories': [
                {'slug': slug, 'label': label}
                for slug, label in COURSE_CATEGORIES
            ],
        },
    }
    functions.log_admin_action(
        admin_name,
        'visade användaröversikt',
        f'personnummer={normalized_personnummer}',
    )
    return jsonify(response)


@app.post('/admin/api/radera-pdf')
def admin_delete_pdf():
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get('personnummer') or '').strip()
    pdf_id = payload.get('pdf_id')
    if not personnummer or pdf_id is None:
        return jsonify({'status': 'error', 'message': 'Ange personnummer och PDF-id.'}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Ogiltigt personnummer.'}), 400

    try:
        pdf_id_int = int(pdf_id)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Ogiltigt PDF-id.'}), 400

    if not functions.delete_user_pdf(normalized_personnummer, pdf_id_int):
        return (
            jsonify({'status': 'error', 'message': 'PDF kunde inte hittas.'}),
            404,
        )

    functions.log_admin_action(
        admin_name,
        'raderade PDF',
        f'personnummer={normalized_personnummer}, pdf_id={pdf_id_int}',
    )
    return jsonify({'status': 'success', 'message': 'PDF borttagen.'})


@app.post('/admin/api/uppdatera-pdf')
def admin_update_pdf():
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get('personnummer') or '').strip()
    pdf_id = payload.get('pdf_id')
    categories = payload.get('categories')
    if not isinstance(categories, list):
        return jsonify({'status': 'error', 'message': 'Kategorier måste vara en lista.'}), 400
    if not personnummer or pdf_id is None:
        return jsonify({'status': 'error', 'message': 'Ange personnummer och PDF-id.'}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Ogiltigt personnummer.'}), 400
    try:
        pdf_id_int = int(pdf_id)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Ogiltigt PDF-id.'}), 400

    try:
        normalized_categories = normalize_category_slugs(categories)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Ogiltig kategori vald.'}), 400

    if not functions.update_pdf_categories(
        normalized_personnummer, pdf_id_int, normalized_categories
    ):
        return (
            jsonify({'status': 'error', 'message': 'PDF kunde inte uppdateras.'}),
            404,
        )

    functions.log_admin_action(
        admin_name,
        'uppdaterade PDF-kategorier',
        f'personnummer={normalized_personnummer}, pdf_id={pdf_id_int}, kategorier={";".join(normalized_categories)}',
    )
    return jsonify({'status': 'success', 'message': 'Kategorier uppdaterade.'})


@app.post('/admin/api/skicka-aterstallning')
def admin_send_password_reset():
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get('personnummer') or '').strip()
    email = (payload.get('email') or '').strip()
    if not personnummer or not email:
        return jsonify({'status': 'error', 'message': 'Ange både personnummer och e-post.'}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Ogiltigt personnummer.'}), 400

    try:
        token = functions.create_password_reset_token(normalized_personnummer, email)
    except ValueError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 404
    except Exception:
        logger.exception("Misslyckades att skapa återställningstoken")
        return jsonify({'status': 'error', 'message': 'Kunde inte skapa återställning.'}), 500

    link = url_for('password_reset', token=token, _external=True)
    try:
        send_password_reset_email(email, link)
    except RuntimeError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 500

    functions.log_admin_action(
        admin_name,
        'skickade lösenordsåterställning',
        f'personnummer={normalized_personnummer}',
    )
    return jsonify({'status': 'success', 'message': 'Återställningsmejl skickat.', 'link': link})


@app.get('/admin/avancerat')
def admin_advanced():
    if not session.get('admin_logged_in'):
        logger.warning("Unauthorized admin advanced GET")
        return redirect('/login_admin')
    tables = sorted(functions.TABLE_REGISTRY.keys())
    return render_template('admin_advanced.html', tables=tables)


@app.get('/admin/advanced/api/schema/<table_name>')
def admin_advanced_schema(table_name: str):
    _require_admin()
    try:
        schema = functions.get_table_schema(table_name)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Okänd tabell.'}), 404
    return jsonify({'status': 'success', 'schema': schema})


@app.get('/admin/advanced/api/rows/<table_name>')
def admin_advanced_rows(table_name: str):
    _require_admin()
    search_term = request.args.get('sok')
    limit = request.args.get('limit', type=int) or 100
    try:
        rows = functions.fetch_table_rows(table_name, search_term, limit)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Okänd tabell.'}), 404
    return jsonify({'status': 'success', 'rows': rows})


@app.post('/admin/advanced/api/rows/<table_name>')
def admin_advanced_create(table_name: str):
    admin_name = _require_admin()
    values = request.get_json(silent=True) or {}
    try:
        row = functions.create_table_row(table_name, values)
    except ValueError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    functions.log_admin_action(
        admin_name,
        'skapade post',
        f'tabell={table_name}',
    )
    return jsonify({'status': 'success', 'row': row}), 201


@app.put('/admin/advanced/api/rows/<table_name>/<int:row_id>')
def admin_advanced_update(table_name: str, row_id: int):
    admin_name = _require_admin()
    values = request.get_json(silent=True) or {}
    try:
        updated = functions.update_table_row(table_name, row_id, values)
    except ValueError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    if not updated:
        return jsonify({'status': 'error', 'message': 'Posten hittades inte.'}), 404
    functions.log_admin_action(
        admin_name,
        'uppdaterade post',
        f'tabell={table_name}, id={row_id}',
    )
    return jsonify({'status': 'success'})


@app.delete('/admin/advanced/api/rows/<table_name>/<int:row_id>')
def admin_advanced_delete(table_name: str, row_id: int):
    admin_name = _require_admin()
    try:
        deleted = functions.delete_table_row(table_name, row_id)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Okänd tabell.'}), 404
    if not deleted:
        return jsonify({'status': 'error', 'message': 'Posten hittades inte.'}), 404
    functions.log_admin_action(
        admin_name,
        'raderade post',
        f'tabell={table_name}, id={row_id}',
    )
    return jsonify({'status': 'success'})


@app.route('/verify_certificate/<personnummer>', methods=['GET'])
def verify_certificate_route(personnummer):
    # Allow an admin to verify whether a user's certificate is confirmed.
    #
    # Uses a cached lookup to avoid repeated database queries for the same
    # ``personnummer``. Returns a JSON response indicating the verification
    # status. If the certificate isn't verified, an informative message is sent
    # back to the administrator.
    if not session.get('admin_logged_in'):
        logger.warning("Unauthorized certificate verification attempt")
        return redirect('/login_admin')

    if functions.verify_certificate(personnummer):
        return jsonify({'status': 'success', 'verified': True})
    return jsonify({
        'status': 'error',
        'message': "Användarens certifikat är inte verifierat",
    }), 404
@app.route("/error")
def error():
    # Intentionally raise an error to test the 500 page.
    # This will cause a 500 Internal Server Error
    raise Exception("Testing 500 error page")

@app.route('/login_admin', methods=['POST', 'GET'])
def login_admin():
    # Authenticate an administrator for access to the admin panel.
    if request.method == 'POST':

        admin_password = os.getenv('admin_password')
        admin_username = os.getenv('admin_username')
        if request.form['username'] == admin_username and request.form['password'] == admin_password:
            session['admin_logged_in'] = True
            session['admin_username'] = admin_username
            logger.info("Admin %s logged in", admin_username)
            return redirect('/admin')
        else:
            logger.warning("Invalid admin login attempt for %s", request.form['username'])
            return jsonify({'status': 'error', 'message': 'Ogiltiga inloggningsuppgifter'})
    elif request.method == 'GET':
        logger.debug("Rendering admin login page")
        return render_template('admin_login.html')
    else:
        logger.warning("Invalid request method %s to login_admin", request.method)
        return jsonify({'status': 'error', 'message': 'Ogiltig HTTP-metod', 'method': request.method})


@app.route('/logout')
def logout():
    # Logga ut både admin och användare.
    logger.info("Logging out user and admin")
    session.pop('user_logged_in', None)
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session.pop('personnummer', None)
    return redirect('/')

@app.errorhandler(500)
def internal_server_error(_):
    logger.error("500 Internal Server Error: %s", request.path)
    # Visa en användarvänlig 500-sida när ett serverfel inträffar.
    return render_template('500.html', time=time.time()), 500


@app.errorhandler(409)
def conflict_error(_):
    # Visa en användarvänlig 409-sida vid konflikt.
    logger.error("409 Conflict: %s", request.path)
    return render_template('409.html'), 409

@app.errorhandler(404)
def page_not_found(_):
    # Visa en användarvänlig 404-sida när en sida saknas.
    logger.warning("Page not found: %s", request.path)
    return render_template('404.html'), 404

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    # Format a POSIX timestamp for display in templates.
    import datetime
    return datetime.datetime.fromtimestamp(value).strftime(format)

if __name__ == '__main__':
    logger.critical("Starting app from app.py, Debug is enabled")
    app.run(
        debug=True,
        host='0.0.0.0',
        port=int(os.getenv('PORT', 80)),
    )
