 # Flask application for issuing and serving course certificates.

from __future__ import annotations

from collections import deque
from functools import partial
import hmac
import logging
import os
import secrets
import time
from typing import Sequence

from flask import (
    Flask,
    Response,
    abort,
    current_app,
    flash,
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
from werkzeug.middleware.proxy_fix import ProxyFix

from config_loader import load_environment
from logging_utils import configure_module_logger, mask_hash

from course_categories import (
    COURSE_CATEGORIES,
    labels_for_slugs,
    normalize_category_slugs,
)

from services import email as email_service


load_environment()

import functions



ALLOWED_MIMES = {'application/pdf'}

_CSRF_SESSION_KEY = "csrf_token"
_PUBLIC_FORM_LIMIT = 5
_PUBLIC_FORM_WINDOW = 60 * 60  # 1 timme
_public_form_attempts: dict[str, deque[float]] = {}


def _ensure_csrf_token() -> str:
    token = session.get(_CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_CSRF_SESSION_KEY] = token
    return token


def _extract_csrf_token() -> str | None:
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        token = payload.get("csrf_token")
        if token:
            return str(token)
    token = request.headers.get("X-CSRF-Token")
    if token:
        return token
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        form_token = request.form.get("csrf_token")
        if form_token:
            return form_token
    return request.args.get("csrf_token")


def _validate_csrf_token() -> bool:
    expected = session.get(_CSRF_SESSION_KEY)
    candidate = _extract_csrf_token()
    if not expected or not candidate:
        return False
    try:
        return hmac.compare_digest(str(candidate), str(expected))
    except Exception:
        return False


def _get_request_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def _register_public_submission(ip: str) -> bool:
    now = time.time()
    bucket = _public_form_attempts.setdefault(ip, deque())
    while bucket and now - bucket[0] > _PUBLIC_FORM_WINDOW:
        bucket.popleft()
    if len(bucket) >= _PUBLIC_FORM_LIMIT:
        return False
    bucket.append(now)
    return True


def _as_bool(value: str | None) -> bool:
    # Tolka strängar som booleska värden.
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "on", "ja", "yes"}

logger = configure_module_logger(__name__)
logger.setLevel(logging.INFO)
# functions.create_test_user()  # Skapa en testanvändare vid start




def _trusted_proxy_hops(raw_value: str | None) -> int:
    # Tolka TRUSTED_PROXY_COUNT och hantera ogiltiga värden på ett säkert sätt.
    default_hops = 1
    if raw_value is None or raw_value.strip() == "":
        return default_hops

    try:
        hops = int(raw_value)
    except ValueError:
        logger.warning(
            "Ogiltigt värde för TRUSTED_PROXY_COUNT (%s) – använder standardvärdet 1.",
            raw_value,
        )
        return default_hops

    if hops < 0:
        logger.warning(
            "TRUSTED_PROXY_COUNT kan inte vara negativt – proxystödet stängs av.",
        )
        return 0

    return hops


def _configure_proxy_fix(app: Flask) -> None:
    # Aktivera ProxyFix så att Flask litar på headers från den externa proxyn.
    hops = _trusted_proxy_hops(os.getenv("TRUSTED_PROXY_COUNT"))
    if hops > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=hops,
            x_proto=hops,
            x_host=hops,
            x_port=hops,
        )
        logger.info("Aktiverar ProxyFix med %s betrodda proxyhopp", mask_hash(str(hops)))
    else:
        logger.info("ProxyFix är inaktiverad (TRUSTED_PROXY_COUNT=%s)", os.getenv("TRUSTED_PROXY_COUNT", "0"))


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
    _configure_proxy_fix(app)
    app.secret_key = os.getenv('secret_key')
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

    demo_defaults = {
        "user_email": os.getenv("DEMO_USER_EMAIL", "demo.anvandare@example.com"),
        "user_name": os.getenv("DEMO_USER_NAME", "Demoanvändare"),
        "user_personnummer": os.getenv("DEMO_USER_PERSONNUMMER", "199001011234"),
        "user_password": os.getenv("DEMO_USER_PASSWORD", "DemoLösenord1!"),
        "supervisor_email": os.getenv("DEMO_SUPERVISOR_EMAIL", "demo.handledare@example.com"),
        "supervisor_name": os.getenv("DEMO_SUPERVISOR_NAME", "Demohandledare"),
        "supervisor_password": os.getenv("DEMO_SUPERVISOR_PASSWORD", "DemoHandledare1!"),
    }

    app.config["IS_DEMO"] = _as_bool(os.getenv("ENABLE_DEMO_MODE"))
    app.config["DEMO_SITE_URL"] = os.getenv("DEMO_SITE_URL", "").strip()
    app.config["DEMO_CREDENTIALS"] = {
        "user_personnummer": demo_defaults["user_personnummer"],
        "user_password": demo_defaults["user_password"],
        "supervisor_email": demo_defaults["supervisor_email"],
        "supervisor_password": demo_defaults["supervisor_password"],
    }

    if app.config["IS_DEMO"]:
        logger.info("Demoläge aktiverat – initierar exempeldata")
        functions.ensure_demo_data(
            user_email=demo_defaults["user_email"],
            user_name=demo_defaults["user_name"],
            user_personnummer=demo_defaults["user_personnummer"],
            user_password=demo_defaults["user_password"],
            supervisor_email=demo_defaults["supervisor_email"],
            supervisor_name=demo_defaults["supervisor_name"],
            supervisor_password=demo_defaults["supervisor_password"],
        )

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





def _require_admin() -> str:
    if not session.get("admin_logged_in"):
        abort(403)
    return session.get("admin_username", "okänd")


def _require_supervisor() -> tuple[str, str]:
    if not session.get("supervisor_logged_in"):
        abort(403)
    email_hash = session.get("supervisor_email_hash")
    if not email_hash:
        abort(403)
    supervisor_name = session.get("supervisor_name") or functions.get_supervisor_name_by_hash(
        email_hash
    )
    if supervisor_name:
        session["supervisor_name"] = supervisor_name
    return email_hash, supervisor_name or "Handledare"

@app.context_processor
def inject_flags():
    # Expose flags indicating debug and demo-läge to Jinja templates.
    return {
        "IS_DEV": current_app.debug,
        "IS_DEMO": current_app.config.get("IS_DEMO", False),
        "DEMO_SITE_URL": current_app.config.get("DEMO_SITE_URL", ""),
        "DEMO_CREDENTIALS": current_app.config.get("DEMO_CREDENTIALS", {}),
    }



def save_pdf_for_user(
    pnr: str, file_storage, categories: Sequence[str]
) -> dict[str, str | int | Sequence[str]]:
    # Validate and store a PDF in the database for the provided personnummer.
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

    pnr_norm = functions.normalize_personnummer(pnr)
    pnr_hash = functions.hash_value(pnr_norm)
    logger.debug("Saving PDF for person %s", mask_hash(pnr_hash))

    selected_categories = normalize_category_slugs(categories)
    if len(selected_categories) != 1:
        logger.error(
            "Invalid number of categories (%d) for hash %s",
            len(selected_categories),
            mask_hash(pnr_hash),
        )
        raise ValueError("Exakt en kurskategori måste väljas.")

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
    logger.info("Stored PDF for %s as id %s", mask_hash(pnr_hash), pdf_id)
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


@app.route('/handledare/skapa/<email_hash>', methods=['GET', 'POST'])
def supervisor_create(email_hash: str):
    logger.info("Handling supervisor creation for hash %s", email_hash)
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm = request.form.get('confirm', '').strip()
        if password != confirm:
            return render_template(
                'create_supervisor.html',
                error='Lösenorden måste matcha.',
                invalid=False,
            )
        try:
            if not functions.supervisor_activate_account(email_hash, password):
                return render_template(
                    'create_supervisor.html',
                    error='Kontot kunde inte aktiveras. Kontrollera att länken är giltig.',
                    invalid=False,
                )
        except ValueError as exc:
            return render_template(
                'create_supervisor.html',
                error=str(exc),
                invalid=False,
            )
        logger.info("Supervisor account activated for %s", email_hash)
        return redirect(url_for('supervisor_login'))

    if functions.check_pending_supervisor_hash(email_hash):
        return render_template('create_supervisor.html', invalid=False)
    logger.warning("Supervisor hash %s not found during activation", email_hash)
    return render_template('create_supervisor.html', invalid=True)


@app.route('/handledare/login', methods=['GET', 'POST'])
def supervisor_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        if not email or not password:
            return render_template(
                'supervisor_login.html',
                error='Ogiltiga inloggningsuppgifter.',
            )
        try:
            normalized_email = functions.normalize_email(email)
        except ValueError:
            logger.warning("Ogiltig e-postadress vid handledarinloggning")
            return render_template(
                'supervisor_login.html',
                error='Ogiltiga inloggningsuppgifter.',
            )
        email_hash = functions.hash_value(normalized_email)
        try:
            valid = functions.verify_supervisor_credentials(normalized_email, password)
        except ValueError:
            logger.warning("Ogiltig e-postadress vid handledarinloggning (validering)")
            return render_template(
                'supervisor_login.html',
                error='Ogiltiga inloggningsuppgifter.',
            )
        if not valid:
            logger.warning("Invalid supervisor login for %s", email_hash)
            return render_template(
                'supervisor_login.html',
                error='Ogiltiga inloggningsuppgifter.',
            )

        session['supervisor_logged_in'] = True
        session['supervisor_email_hash'] = email_hash
        supervisor_name = functions.get_supervisor_name_by_hash(email_hash)
        if supervisor_name:
            session['supervisor_name'] = supervisor_name
        logger.info("Supervisor %s logged in", email_hash)
        return redirect(url_for('supervisor_dashboard'))

    return render_template('supervisor_login.html')


@app.route('/handledare', methods=['GET'])
def supervisor_dashboard():
    if not session.get('supervisor_logged_in'):
            return redirect(url_for('supervisor_login'))
    email_hash, supervisor_name = _require_supervisor()
    connections = functions.list_supervisor_connections(email_hash)
    users = []
    for entry in connections:
        person_hash = entry['personnummer_hash']
        username = (entry.get('username') or 'Användare').strip()
        pdfs = functions.get_user_pdfs(person_hash)
        for pdf in pdfs:
            pdf['category_labels'] = labels_for_slugs(pdf.get('categories') or [])
        users.append(
            {
                'personnummer_hash': person_hash,
                'username': username,
                'pdfs': pdfs,
            }
        )

    return render_template(
        'supervisor_dashboard.html',
        supervisor_name=supervisor_name,
        users=users,
    )


@app.route('/handledare/anvandare/<person_hash>/pdf/<int:pdf_id>')
def supervisor_download_pdf(person_hash: str, pdf_id: int):
    email_hash, _ = _require_supervisor()
    if not functions.supervisor_has_access(email_hash, person_hash):
        logger.warning(
            "Supervisor %s attempted to access pdf %s for %s without permission",
            email_hash,
            pdf_id,
            person_hash,
        )
        abort(404)
    pdf = functions.get_pdf_content(person_hash, pdf_id)
    if not pdf:
        abort(404)
    filename, content = pdf
    as_attachment = request.args.get('download', '1') != '0'
    logger.info(
        "Supervisor %s retrieving %s for %s",
        email_hash,
        filename,
        person_hash,
    )
    response = make_response(content)
    response.headers['Content-Type'] = 'application/pdf'
    disposition = 'attachment' if as_attachment else 'inline'
    response.headers['Content-Disposition'] = f"{disposition}; filename=\"{filename}\""
    return response


@app.post('/handledare/dela/<person_hash>/<int:pdf_id>')
def supervisor_share_pdf_route(person_hash: str, pdf_id: int):
    email_hash, supervisor_name = _require_supervisor()
    anchor = request.form.get('anchor', '')
    redirect_target = url_for('supervisor_dashboard')
    if anchor:
        redirect_target += f'#{anchor}'

    if not functions.supervisor_has_access(email_hash, person_hash):
        logger.warning(
            "Supervisor %s attempted to share pdf %s for %s without permission",
            email_hash,
            pdf_id,
            person_hash,
        )
        flash('Åtgärden kunde inte utföras.', 'error')
        return redirect(redirect_target)

    recipient_email = (request.form.get('recipient_email') or '').strip()
    if not recipient_email:
        flash('Ange en e-postadress.', 'error')
        return redirect(redirect_target)

    try:
        normalized_recipient = email_service.normalize_valid_email(recipient_email)
    except ValueError:
        flash('Ogiltig e-postadress.', 'error')
        return redirect(redirect_target)

    pdf = functions.get_pdf_content(person_hash, pdf_id)
    if not pdf:
        flash('Intyget kunde inte hittas.', 'error')
        return redirect(redirect_target)

    owner_name = functions.get_username_by_personnummer_hash(person_hash) or 'Användaren'
    attachments = [(pdf[0], pdf[1])]

    try:
        email_service.send_pdf_share_email(
            normalized_recipient,
            attachments,
            supervisor_name,
            owner_name=owner_name,
        )
    except RuntimeError:
        logger.exception(
            "Failed to share pdf %s for %s by supervisor %s",
            pdf_id,
            person_hash,
            email_hash,
        )
        flash('Ett internt fel inträffade när intyget skulle delas.', 'error')
        return redirect(redirect_target)

    logger.info(
        "Supervisor %s shared pdf %s for %s to %s",
        email_hash,
        pdf_id,
        person_hash,
        normalized_recipient,
    )
    flash('Intyget har skickats via e-post.', 'success')
    return redirect(redirect_target)


@app.post('/handledare/kopplingar/<person_hash>/ta-bort')
def supervisor_remove_connection_route(person_hash: str):
    email_hash, _ = _require_supervisor()
    anchor = request.form.get('anchor', '')
    redirect_target = url_for('supervisor_dashboard')
    if anchor:
        redirect_target += f'#{anchor}'

    if functions.supervisor_remove_connection(email_hash, person_hash):
        logger.info("Supervisor %s removed access to %s", email_hash, person_hash)
        flash('Kopplingen har tagits bort.', 'success')
    else:
        flash('Kopplingen kunde inte tas bort.', 'error')
    return redirect(redirect_target)

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


@app.route('/ansok', methods=['GET', 'POST'])
def apply_account():
    """Visa och hantera ansökningsformuläret."""

    form_errors: list[str] = []
    status_code = 200
    form_data = {
        "account_type": "user",
        "name": "",
        "email": "",
        "orgnr": "",
        "company_name": "",
        "comment": "",
    }

    if request.method == 'POST':
        form_data.update({key: (request.form.get(key, '') or '').strip() for key in form_data})
        if not _validate_csrf_token():
            form_errors.append("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.")
        else:
            client_ip = _get_request_ip()
            if not _register_public_submission(client_ip):
                status_code = 429
                form_errors.append("Du har gjort för många försök. Vänta en stund och prova igen.")
            else:
                try:
                    request_id = functions.create_application_request(
                        form_data["account_type"],
                        form_data["name"],
                        form_data["email"],
                        form_data["orgnr"],
                        form_data["company_name"],
                        form_data["comment"],
                    )
                    logger.info("Ny ansökan %s mottagen från %s", request_id, mask_hash(functions.hash_value(form_data["email"].lower())))
                except ValueError as exc:
                    form_errors.append(str(exc))
                except Exception as exc:  # pragma: no cover - defensiv loggning
                    logger.exception("Kunde inte spara ansökan")
                    form_errors.append("Det gick inte att skicka ansökan just nu. Försök igen senare.")
                else:
                    flash(("success", "Tack! Vi hör av oss så snart vi granskat ansökan."))
                    return redirect(url_for('apply_account'))

    csrf_token = _ensure_csrf_token()
    return (
        render_template(
            'apply.html',
            csrf_token=csrf_token,
            form_data=form_data,
            form_errors=form_errors,
        ),
        status_code,
    )



@app.route('/license', methods=['GET'])
def license():
    # Render the license information page.
    logger.debug("Rendering license page")
    return render_template('license.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Authenticate users using personnummer and password.
    if request.method == 'POST':
        raw_personnummer = request.form['personnummer']
        try:
            personnummer = functions.normalize_personnummer(raw_personnummer)
        except ValueError:
            logger.error("Ogiltigt personnummer angivet vid inloggning")
            return (
                render_template('user_login.html', error='Ogiltiga inloggningsuppgifter'),
                401,
            )

        if personnummer == "" or not personnummer.isnumeric():
            logger.error("Ogiltigt normaliserat personnummer vid inloggning")
            return (
                render_template('user_login.html', error='Ogiltiga inloggningsuppgifter'),
                401,
            )
        password = request.form['password']
        personnummer_hash = functions.hash_value(personnummer)
        if password == "":
            logger.error("Empty password provided for %s", mask_hash(personnummer_hash))
            return (
                render_template('user_login.html', error='Ogiltiga inloggningsuppgifter'),
                401,
            )
        logger.debug("Login attempt for %s", mask_hash(personnummer_hash))
        if functions.check_personnummer_password(personnummer, password):
            session['user_logged_in'] = True
            session['personnummer'] = personnummer_hash
            session['username'] = functions.get_username_by_personnummer_hash(
                personnummer_hash
            )
            logger.info("User %s logged in", mask_hash(personnummer_hash))
            return redirect('/dashboard')
        else:
            logger.warning("Invalid login for %s", mask_hash(personnummer_hash))
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


@app.route('/share_pdf', methods=['POST'])
def share_pdf() -> tuple[Response, int]:
    # Share a PDF with a recipient via e-post.
    if not session.get('user_logged_in'):
        logger.debug("Unauthenticated share attempt")
        return jsonify({'fel': 'Du måste vara inloggad för att dela intyg.'}), 401

    payload = request.get_json(silent=True) or request.form
    if not payload:
        logger.error(f"Empty payload in share_pdf:{payload!r}")
        return jsonify({'fel': 'Ogiltig begäran.'}), 400

    pdf_ids_raw = payload.get('pdf_ids') if hasattr(payload, 'get') else None
    recipient_email = (payload.get('recipient_email', '') if hasattr(payload, 'get') else '').strip()

    if pdf_ids_raw is None and hasattr(payload, 'get'):
        pdf_id_raw = payload.get('pdf_id')
        if pdf_id_raw is not None:
            pdf_ids_raw = [pdf_id_raw]

    if pdf_ids_raw is None:
        logger.debug(f"No pdf_ids provided in share_pdf: {payload!r}")
        return jsonify({'fel': 'Ogiltigt intyg angivet.'}), 400

    if isinstance(pdf_ids_raw, (str, bytes)):
        candidate_ids = [pdf_ids_raw]
    elif isinstance(pdf_ids_raw, (list, tuple, set)):
        candidate_ids = list(pdf_ids_raw)
    else:
        candidate_ids = [pdf_ids_raw]

    pdf_ids: list[int] = []
    seen_ids: set[int] = set()
    for raw_id in candidate_ids:
        try:
            pdf_id = int(raw_id)
        except (TypeError, ValueError):
            logger.warning("Invalid pdf_id provided for sharing: %r", raw_id)
            return jsonify({'fel': 'Ogiltigt intyg angivet.'}), 400
        if pdf_id in seen_ids:
            continue
        seen_ids.add(pdf_id)
        pdf_ids.append(pdf_id)

    if not pdf_ids:
        logger.debug(f"Empty pdf_ids after processing in share_pdf: {payload!r}")
        return jsonify({'fel': 'Ogiltigt intyg angivet.'}), 400

    if not recipient_email:
        logger.debug("Empty recipient_email in share_pdf: %r", payload)
        return jsonify({'fel': 'Ange en e-postadress.'}), 400

    pnr_hash = session.get('personnummer')
    if not pnr_hash:
        logger.error("Share request missing personnummer in session: %r", session)
        return jsonify({'fel': 'Saknar användaruppgifter.'}), 400

    attachments: list[tuple[str, bytes]] = []

    for pdf_id in pdf_ids:
        pdf = functions.get_pdf_content(pnr_hash, pdf_id)
        if not pdf:
            logger.debug("PDF %s not found for user %s when sharing", pdf_id, pnr_hash)
            return jsonify({'fel': 'Intyget kunde inte hittas.'}), 404
        filename, content = pdf
        attachments.append((filename, content))

    sender_name = session.get('username')
    if not sender_name:
        sender_name = functions.get_username_by_personnummer_hash(pnr_hash)
        if sender_name:
            session['username'] = sender_name

    sender_display = (sender_name or '').strip() or 'En användare'

    try:
        normalized_recipient = email_service.normalize_valid_email(recipient_email)
    except ValueError:
        logger.debug("Invalid recipient_email in share_pdf: %r", recipient_email)
        return jsonify({'fel': 'Ogiltig e-postadress.'}), 400

    if normalized_recipient != recipient_email:
        logger.debug(
            "Normalized share recipient email from %r to %s",
            recipient_email,
            normalized_recipient,
        )

    try:
        email_service.send_pdf_share_email(
            normalized_recipient,
            attachments,
            sender_display,
        )
    except RuntimeError as exc:
        logger.exception(
            "Failed to share pdf %s from %s to %s",
            pdf_ids,
            pnr_hash,
            normalized_recipient,
        )
        return jsonify({'fel': 'Ett internt fel har inträffat.'}), 500

    logger.info(
        "User %s delade intyg %s med %s",
        pnr_hash,
        pdf_ids,
        normalized_recipient,
    )
    success_message = (
        'Intyget har skickats via e-post.'
        if len(attachments) == 1
        else 'Intygen har skickats via e-post.'
    )
    return jsonify({'meddelande': success_message}), 200


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
            return redirect('/error', code=401)

        try:
            # --- Grab form data ---
            email_input = request.form.get('email', '').strip()
            username = request.form.get('username', '').strip()
            personnummer = functions.normalize_personnummer(request.form.get('personnummer', '').strip())
            normalized_email = functions.normalize_email(email_input)
            email = normalized_email
            email_hash = functions.hash_value(email)
            pnr_hash = functions.hash_value(personnummer)

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
                mask_hash(pnr_hash),
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
            pending_exists = functions.check_pending_user_hash(pnr_hash)

            # --- Save PDFs ---
            pdf_records = [
                save_pdf_for_user(personnummer, file_storage, [category])
                for file_storage, category in zip(pdf_files, normalized_categories)
            ]

            # --- Return early for existing or pending users ---
            if user_exists:
                logger.info(
                    "PDFs uploaded for existing user %s (%d files)",
                    mask_hash(pnr_hash),
                    len(pdf_records),
                )
                return jsonify({'status': 'success', 'message': 'PDF:er uppladdade för befintlig användare'})

            if pending_exists:
                logger.info(
                    "PDFs uploaded for pending user %s (%d files)",
                    mask_hash(pnr_hash),
                    len(pdf_records),
                )
                return jsonify({'status': 'success', 'message': 'Användaren väntar redan på aktivering. PDF:er uppladdade.'})

            # --- Create new pending user ---
            if functions.admin_create_user(email, username, personnummer):
                link = url_for('create_user', pnr_hash=pnr_hash, _external=True)
                try:
                    email_service.send_creation_email(email, link)
                except RuntimeError as e:
                    logger.error(
                        "Failed to send creation email to %s",
                        mask_hash(email_hash),
                        exc_info=True,
                    )
                    return jsonify({'status': 'error', 'message': 'Det gick inte att skicka inloggningslänken via e-post.'}), 500

                logger.info("Admin created user %s", mask_hash(pnr_hash))
                return jsonify({'status': 'success', 'message': 'Användare skapad', 'link': link})

            logger.error("Failed to create pending user for %s", mask_hash(pnr_hash))
            return jsonify({'status': 'error', 'message': 'Kunde inte skapa användare'}), 500

        except ValueError as ve:
            logger.error("Value error during admin upload: %s", ve)
            return jsonify({'status': 'error', 'message': 'Felaktiga användardata.'}), 400
        except Exception as e:
            logger.exception("Server error during admin upload", exc_info=e)
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


@app.route('/admin/ansokningar', methods=['GET'])
def admin_applications():
    if not session.get('admin_logged_in'):
        return redirect('/login_admin')
    csrf_token = _ensure_csrf_token()
    return render_template('admin_applications.html', csrf_token=csrf_token)


def _serialize_application_row(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "account_type": row.get("account_type"),
        "name": row.get("name"),
        "email": row.get("email"),
        "orgnr_normalized": row.get("orgnr_normalized"),
        "company_name": row.get("company_name"),
        "comment": row.get("comment"),
        "status": row.get("status"),
        "reviewed_by": row.get("reviewed_by"),
        "decision_reason": row.get("decision_reason"),
        "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
        "updated_at": row.get("updated_at").isoformat() if row.get("updated_at") else None,
        "reviewed_at": row.get("reviewed_at").isoformat() if row.get("reviewed_at") else None,
    }


@app.get('/admin/api/ansokningar')
def admin_list_applications():
    _require_admin()
    status = request.args.get('status')
    try:
        rows = functions.list_application_requests(status)
    except ValueError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400

    serialized = [_serialize_application_row(row) for row in rows]
    return jsonify({'status': 'success', 'data': serialized})


@app.get('/admin/api/ansokningar/<int:application_id>')
def admin_get_application(application_id: int):
    _require_admin()
    row = functions.get_application_request(application_id)
    if not row:
        return jsonify({'status': 'error', 'message': 'Ansökan hittades inte.'}), 404
    return jsonify({'status': 'success', 'data': _serialize_application_row(row)})


@app.post('/admin/api/ansokningar/<int:application_id>/godkann')
def admin_approve_application(application_id: int):
    admin_name = _require_admin()
    if not _validate_csrf_token():
        return jsonify({'status': 'error', 'message': 'Ogiltig CSRF-token.'}), 400

    try:
        result = functions.approve_application_request(application_id, admin_name)
    except ValueError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception:
        logger.exception("Misslyckades att godkänna ansökan %s", application_id)
        return jsonify({'status': 'error', 'message': 'Kunde inte godkänna ansökan.'}), 500

    email_error = None
    try:
        email_service.send_application_approval_email(
            result['email'], result['account_type'], result['company_name']
        )
    except RuntimeError as exc:
        logger.exception("Misslyckades att skicka godkännandemejl för ansökan %s", application_id)
        email_error = str(exc)

    masked_email = mask_hash(functions.hash_value(result['email']))
    functions.log_admin_action(
        admin_name,
        'godkände ansökan',
        f'application_id={application_id}, email={masked_email}',
    )

    payload = {'status': 'success', 'data': result}
    if email_error:
        payload['email_warning'] = 'Konto godkänt men e-post kunde inte skickas.'
    return jsonify(payload)


@app.post('/admin/api/ansokningar/<int:application_id>/avslag')
def admin_reject_application(application_id: int):
    admin_name = _require_admin()
    if not _validate_csrf_token():
        return jsonify({'status': 'error', 'message': 'Ogiltig CSRF-token.'}), 400

    payload = request.get_json(silent=True) or {}
    reason = (payload.get('reason') or '').strip()

    try:
        result = functions.reject_application_request(application_id, admin_name, reason)
    except ValueError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception:
        logger.exception("Misslyckades att avslå ansökan %s", application_id)
        return jsonify({'status': 'error', 'message': 'Kunde inte avslå ansökan.'}), 500

    email_error = None
    try:
        email_service.send_application_rejection_email(
            result['email'], result['company_name'], result['reason']
        )
    except RuntimeError as exc:
        logger.exception("Misslyckades att skicka avslag för ansökan %s", application_id)
        email_error = str(exc)

    masked_email = mask_hash(functions.hash_value(result['email']))
    functions.log_admin_action(
        admin_name,
        'avslog ansökan',
        f'application_id={application_id}, email={masked_email}',
    )

    response_payload = {'status': 'success', 'data': result}
    if email_error:
        response_payload['email_warning'] = 'Ansökan avslogs men e-post kunde inte skickas.'
    return jsonify(response_payload)


@app.post('/admin/api/oversikt')
def admin_user_overview():
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get('personnummer') or '').strip()
    if not personnummer:
        logging.debug("Admin overview without personnummer: ", extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ange personnummer.'}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        logging.debug("Admin overview with invalid personnummer: %s", personnummer, extra={'admin': admin_name})
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
        f'personnummer_hash={pnr_hash}',
    )
    logging.debug("Admin overview for %s with %d pdfs", mask_hash(pnr_hash), len(pdfs), extra={'admin': admin_name})
    return jsonify(response)


@app.post('/admin/api/radera-pdf')
def admin_delete_pdf():
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get('personnummer') or '').strip()
    pdf_id = payload.get('pdf_id')
    if not personnummer or pdf_id is None:
        logging.debug("Admin delete_pdf without personnummer or pdf_id", extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ange personnummer och PDF-id.'}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        logging.debug("Admin delete_pdf with invalid personnummer: %s", personnummer, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ogiltigt personnummer.'}), 400

    try:
        pdf_id_int = int(pdf_id)
    except (ValueError, TypeError):
        logging.debug("Admin delete_pdf with invalid pdf_id: %s", pdf_id, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ogiltigt PDF-id.'}), 400

    if not functions.delete_user_pdf(normalized_personnummer, pdf_id_int):
        return (
            jsonify({'status': 'error', 'message': 'PDF kunde inte hittas.'}),
            404,
        )

    pnr_hash = functions.hash_value(normalized_personnummer)
    functions.log_admin_action(
        admin_name,
        'raderade PDF',
        f'personnummer_hash={pnr_hash}, pdf_id={pdf_id_int}',
    )
    logging.info("Admin deleted pdf %s for %s", pdf_id_int, mask_hash(pnr_hash), extra={'admin': admin_name})
    return jsonify({'status': 'success', 'message': 'PDF borttagen.'})


@app.post('/admin/api/uppdatera-pdf')
def admin_update_pdf():
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get('personnummer') or '').strip()
    pdf_id = payload.get('pdf_id')
    categories = payload.get('categories')
    if not isinstance(categories, list):
        logging.debug("Admin update_pdf with invalid categories: %r", categories, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Kategorier måste vara en lista.'}), 400
    if not personnummer or pdf_id is None:
        logging.debug("Admin update_pdf without personnummer or pdf_id", extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ange personnummer och PDF-id.'}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        logging.debug("Admin update_pdf with invalid personnummer: %s", personnummer, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ogiltigt personnummer.'}), 400
    try:
        pdf_id_int = int(pdf_id)
    except (ValueError, TypeError):
        logging.debug("Admin update_pdf with invalid pdf_id: %s", pdf_id, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ogiltigt PDF-id.'}), 400

    try:
        normalized_categories = normalize_category_slugs(categories)
    except ValueError:
        logging.debug("Admin update_pdf with invalid categories: %r", categories, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ogiltig kategori vald.'}), 400

    if not functions.update_pdf_categories(
        normalized_personnummer, pdf_id_int, normalized_categories
    ):
        return (
            jsonify({'status': 'error', 'message': 'PDF kunde inte uppdateras.'}),
            404,
        )

    pnr_hash = functions.hash_value(normalized_personnummer)
    functions.log_admin_action(
        admin_name,
        'uppdaterade PDF-kategorier',
        f'personnummer_hash={pnr_hash}, pdf_id={pdf_id_int}, kategorier={";".join(normalized_categories)}',
    )
    logging.info("Admin updated categories for pdf %s for %s", pdf_id_int, mask_hash(pnr_hash), extra={'admin': admin_name})
    return jsonify({'status': 'success', 'message': 'Kategorier uppdaterade.'})


@app.post('/admin/api/skicka-aterstallning')
def admin_send_password_reset():
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get('personnummer') or '').strip()
    email = (payload.get('email') or '').strip()
    if not personnummer or not email:
        logging.debug("Admin send_password_reset without personnummer or email", extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ange både personnummer och e-post.'}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        logging.debug("Admin send_password_reset with invalid personnummer: %s", personnummer, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ogiltigt personnummer.'}), 400

    try:
        token = functions.create_password_reset_token(normalized_personnummer, email)
    except ValueError as exc:
        logger.exception(f"Misslyckades att skapa återställningstoken: {exc}")
        return jsonify({'status': 'error', 'message': 'Kunde inte skapa återställning.'}), 404
    except Exception as e:
        logger.exception(f"Misslyckades att skapa återställningstoken: {e}")
        return jsonify({'status': 'error', 'message': 'Kunde inte skapa återställning.'}), 500

    link = url_for('password_reset', token=token, _external=True)
    try:
        email_service.send_password_reset_email(email, link)
    except RuntimeError as exc:
        logger.exception(f"Misslyckades att skicka återställningsmejl: {exc}")
        return jsonify({'status': 'error', 'message': 'Kunde inte skicka återställningsmejl.'}), 500

    pnr_hash = functions.hash_value(normalized_personnummer)
    email_hash = functions.hash_value(functions.normalize_email(email))
    functions.log_admin_action(
        admin_name,
        'skickade lösenordsåterställning',
        f'personnummer_hash={pnr_hash}, email_hash={email_hash}',
    )
    logging.info("Admin sent password reset for %s to %s", mask_hash(pnr_hash), mask_hash(email_hash), extra={'admin': admin_name})
    return jsonify({'status': 'success', 'message': 'Återställningsmejl skickat.', 'link': link})


@app.post('/admin/api/handledare/skapa')
def admin_create_supervisor_route():
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    email = (payload.get('email') or '').strip()
    name = (payload.get('name') or '').strip()
    if not email or not name:
        logging.debug("Admin create_supervisor without email or name", extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ange namn och e-post.'}), 400

    try:
        normalized_email = functions.normalize_email(email)
    except ValueError:
        logging.debug("Admin create_supervisor with invalid email: %s", email, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ogiltig e-postadress.'}), 400

    if not functions.admin_create_supervisor(normalized_email, name):
        return (
            jsonify({'status': 'error', 'message': 'Handledaren finns redan eller väntar på aktivering.'}),
            409,
        )

    email_hash = functions.get_supervisor_email_hash(normalized_email)
    link = url_for('supervisor_create', email_hash=email_hash, _external=True)

    try:
        email_service.send_creation_email(normalized_email, link)
    except RuntimeError:
        logger.exception("Failed to send supervisor creation email to %s", email_hash)
        return (
            jsonify({'status': 'error', 'message': 'Det gick inte att skicka inloggningslänken.'}),
            500,
        )

    functions.log_admin_action(
        admin_name,
        'skapade handledare',
        f'email_hash={email_hash}',
    )
    logging.info("Admin created supervisor %s", mask_hash(email_hash), extra={'admin': admin_name})
    return jsonify({'status': 'success', 'message': 'Handledare skapad.', 'link': link})


@app.post('/admin/api/handledare/koppla')
def admin_link_supervisor_route():
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    email = (payload.get('email') or '').strip()
    personnummer = (payload.get('personnummer') or '').strip()
    if not email or not personnummer:
        logging.debug("Admin link_supervisor without email or personnummer", extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ange handledarens e-post och personnummer.'}), 400

    try:
        success, reason = functions.admin_link_supervisor_to_user(email, personnummer)
    except ValueError:
        logging.debug("Admin link_supervisor with invalid email or personnummer: %s, %s", email, personnummer, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ogiltiga användaruppgifter.'}), 400

    if not success:
        status_code = 400
        message = 'Åtgärden kunde inte utföras.'
        if reason == 'missing_supervisor':
            status_code = 404
            message = 'Handledaren finns inte.'
        elif reason == 'missing_user':
            status_code = 404
            message = 'Användaren finns inte.'
        elif reason == 'exists':
            status_code = 409
            message = 'Kopplingen finns redan.'
        logging.debug("Admin link_supervisor failed: %s", reason, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': message}), status_code

    normalized_email = functions.normalize_email(email)
    normalized_personnummer = functions.normalize_personnummer(personnummer)
    email_hash = functions.hash_value(normalized_email)
    personnummer_hash = functions.hash_value(normalized_personnummer)
    functions.log_admin_action(
        admin_name,
        'kopplade handledare',
        f'email_hash={email_hash}, personnummer_hash={personnummer_hash}',
    )
    logging.info("Admin linked supervisor %s to user %s", mask_hash(email_hash), mask_hash(personnummer_hash), extra={'admin': admin_name})
    return jsonify({'status': 'success', 'message': 'Handledaren har kopplats till användaren.'})


@app.post('/admin/api/handledare/oversikt')
def admin_supervisor_overview():
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    email = (payload.get('email') or '').strip()
    if not email:
        logging.debug("Admin supervisor_overview without email", extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ange handledarens e-post.'}), 400

    try:
        email_hash = functions.get_supervisor_email_hash(email)
    except ValueError:
        logging.debug("Admin supervisor_overview with invalid email: %s", email, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Ogiltig e-postadress.'}), 400

    overview = functions.get_supervisor_overview(email_hash)
    if not overview:
        logging.debug("Admin supervisor_overview not found for email: %s", email, extra={'admin': admin_name})
        return jsonify({'status': 'error', 'message': 'Handledaren hittades inte.'}), 404

    normalized_email = functions.normalize_email(email)
    functions.log_admin_action(
        admin_name,
        'visade handledaröversikt',
        f'email_hash={functions.hash_value(normalized_email)}',
    )
    logging.debug("Admin supervisor_overview for %s with %d users", mask_hash(functions.hash_value(normalized_email)), len(overview.get('users', [])), extra={'admin': admin_name})
    return jsonify({'status': 'success', 'data': overview})

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
        logging.debug("Admin advanced schema with unknown table: %s", table_name)
        return jsonify({'status': 'error', 'message': 'Okänd tabell.'}), 404
    logging.debug("Admin advanced schema for table: %s", table_name)
    return jsonify({'status': 'success', 'schema': schema})


@app.get('/admin/advanced/api/rows/<table_name>')
def admin_advanced_rows(table_name: str):
    _require_admin()
    search_term = request.args.get('sok')
    limit = request.args.get('limit', type=int) or 100
    try:
        rows = functions.fetch_table_rows(table_name, search_term, limit)
    except ValueError:
        logging.debug("Admin advanced rows with unknown table: %s", table_name)
        return jsonify({'status': 'error', 'message': 'Okänd tabell.'}), 404
    logging.debug("Admin advanced rows for table: %s, search: %r, limit: %d", table_name, search_term, limit)
    return jsonify({'status': 'success', 'rows': rows})


@app.post('/admin/advanced/api/rows/<table_name>')
def admin_advanced_create(table_name: str):
    admin_name = _require_admin()
    values = request.get_json(silent=True) or {}
    try:
        row = functions.create_table_row(table_name, values)
    except ValueError as exc:
        logger.warning(f"Error in create_table_row: {exc}")
        return jsonify({'status': 'error', 'message': 'Kunde inte skapa posten.'}), 400
    functions.log_admin_action(
        admin_name,
        'skapade post',
        f'tabell={table_name}',
    )
    logging.info("Admin created row in table %s: %s", table_name, row, extra={'admin': admin_name})
    return jsonify({'status': 'success', 'row': row}), 201


@app.put('/admin/advanced/api/rows/<table_name>/<int:row_id>')
def admin_advanced_update(table_name: str, row_id: int):
    admin_name = _require_admin()
    values = request.get_json(silent=True) or {}
    try:
        updated = functions.update_table_row(table_name, row_id, values)
    except ValueError as exc:
        logger.exception(f"Failed to update row in table '{table_name}', id={row_id}: {exc}")
        return jsonify({'status': 'error', 'message': 'Felaktiga data.'}), 400
    if not updated:
        logging.debug("Admin advanced update with missing row: table=%s, id=%d", table_name, row_id)
        return jsonify({'status': 'error', 'message': 'Posten hittades inte.'}), 404
    functions.log_admin_action(
        admin_name,
        'uppdaterade post',
        f'tabell={table_name}, id={row_id}',
    )
    logging.info("Admin updated row in table %s, id=%d: %s", table_name, row_id, values, extra={'admin': admin_name})
    return jsonify({'status': 'success'})


@app.delete('/admin/advanced/api/rows/<table_name>/<int:row_id>')
def admin_advanced_delete(table_name: str, row_id: int):
    admin_name = _require_admin()
    try:
        deleted = functions.delete_table_row(table_name, row_id)
    except ValueError:
        logging.debug("Admin advanced delete with unknown table: %s", table_name)
        return jsonify({'status': 'error', 'message': 'Okänd tabell.'}), 404
    if not deleted:
        logging.debug("Admin advanced delete with missing row: table=%s, id=%d", table_name, row_id)
        return jsonify({'status': 'error', 'message': 'Posten hittades inte.'}), 404
    functions.log_admin_action(
        admin_name,
        'raderade post',
        f'tabell={table_name}, id={row_id}',
    )
    logging.info("Admin deleted row in table %s, id=%d", table_name, row_id, extra={'admin': admin_name})
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
        logger.info("Certificate for %s is verified", mask_hash(functions.hash_value(personnummer)))
        return jsonify({'status': 'success', 'verified': True})
    return jsonify({
        'status': 'error',
        'message': "Användarens certifikat är inte verifierat",
    }), 404
    logger.info("Certificate for %s is NOT verified", mask_hash(functions.hash_value(personnummer)))


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
    session.pop('supervisor_logged_in', None)
    session.pop('supervisor_email_hash', None)
    session.pop('supervisor_name', None)
    return redirect('/')


## -------------------------Error Handlers -------------------------##
@app.route("/error")
def error():
    # Intentionally raise an error to test the 500 page.
    # This will cause a 500 Internal Server Error
    raise Exception("Testing 500 error page")
@app.errorhandler(500)
def internal_server_error(_):
    logger.error("500 Internal Server Error: %s", request.path)
    # Visa en användarvänlig 500-sida när ett serverfel inträffar.
    error_code = 500
    error_message = "Ett internt serverfel har inträffat. Vänligen försök igen senare."
    return render_template('error.html', error_code=error_code, error_message=error_message, time=time.time()), 500

@app.errorhandler(401)
def unauthorized_error(_):
    # Visa en användarvänlig 401-sida vid obehörig åtkomst.
    logger.warning("401 Unauthorized: %s", request.path)
    error_code = 401
    error_message = "Du måste vara inloggad för att se denna sida."
    return render_template('error.html', error_code=error_code, error_message=error_message, time=time.time()), 401

@app.errorhandler(409)
def conflict_error(_):
    # Visa en användarvänlig 409-sida vid konflikt.
    logger.error("409 Conflict: %s", request.path)
    error_code = 409
    error_message = "Det uppstod en konflikt vid hantering av din begäran."
    return render_template('error.html', error_code=error_code, error_message=error_message, time=time.time()), 409

@app.errorhandler(404)
def page_not_found(_):
    # Visa en användarvänlig 404-sida när en sida saknas.
    logger.warning("Page not found: %s", request.path)
    error_code = 404
    error_message = "Sidan du letade efter kunde inte hittas."
    return render_template('error.html', error_code=error_code, error_message=error_message, time=time.time()), 404
##----------------------------------------##




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
