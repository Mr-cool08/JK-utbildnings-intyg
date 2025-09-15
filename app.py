"""Flask application for issuing and serving course certificates."""

from datetime import datetime
import logging
import os
import ssl
import time

from email import policy
from email.message import EmailMessage
from smtplib import (
    SMTP,
    SMTPAuthenticationError,
    SMTPException,
    SMTPServerDisconnected,
    SMTP_SSL,
)

from flask import (
    Flask,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

import functions


APP_ROOT = os.path.abspath(os.path.dirname(__file__))
CONFIG_PATH = os.getenv("CONFIG_PATH", "/config/.env")
load_dotenv(CONFIG_PATH)
UPLOAD_ROOT = os.path.join(APP_ROOT, 'uploads')
ALLOWED_MIMES = {'application/pdf'}

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  
logger.propagate = True  
# functions.create_test_user()  # Skapa en testanvändare vid start
def _enable_debug_mode(app: Flask) -> None:
    """Aktivera extra loggning och ev. testdata i debug-läge."""
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
    """Create and configure the Flask application."""
    logger.debug("Loading environment variables and initializing database")
    functions.create_database()
    app = Flask(__name__)
    app.secret_key = os.getenv('secret_key')
    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    app.config['UPLOAD_ROOT'] = UPLOAD_ROOT
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB
    
    with app.app_context():
        if app.debug:
            _enable_debug_mode(app)
            
    logger.debug("Application created with upload root %s", UPLOAD_ROOT)
    return app


app = create_app()


@app.route("/health")
def health() -> tuple[dict, int]:
    """Basic health check endpoint."""
    return {"status": "ok"}, 200


def _send_email(to_email: str, subject: str, html_content: str, log_context: str) -> None:
    """Send an HTML email using the configured SMTP server."""

    to_email = to_email.lower()
    smtp_server = os.getenv("smtp_server")
    smtp_port = int(os.getenv("smtp_port", "587"))
    smtp_user = os.getenv("smtp_user")
    smtp_password = os.getenv("smtp_password")
    smtp_timeout = int(os.getenv("smtp_timeout", "10"))

    if not (smtp_server and smtp_user and smtp_password):
        raise RuntimeError("Saknar env: smtp_server, smtp_user eller smtp_password")

    msg = EmailMessage(policy=policy.SMTP.clone(max_line_length=1000))
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = to_email
    msg.set_content(html_content, subtype="html")

    context = ssl.create_default_context()

    try:
        use_ssl = smtp_port == 465
        logger.debug(
            "Sending %s email via %s:%s (%s, timeout %ss) to %s",
            log_context,
            smtp_server,
            smtp_port,
            "SSL" if use_ssl else "STARTTLS",
            smtp_timeout,
            to_email,
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
                    else:
                        smtp.starttls()
                except (TypeError, ValueError):
                    smtp.starttls()

                if hasattr(smtp, "ehlo"):
                    smtp.ehlo()

            smtp.login(smtp_user, smtp_password)

            if hasattr(smtp, "send_message"):
                smtp.send_message(msg)
            else:
                smtp.sendmail(smtp_user, to_email, msg.as_string())

        logger.info("%s email sent to %s", log_context, to_email)

    except SMTPAuthenticationError as exc:
        logger.exception("SMTP login failed for %s", smtp_user)
        raise RuntimeError("SMTP-inloggning misslyckades") from exc
    except SMTPServerDisconnected as exc:
        logger.exception("Server closed the connection during SMTP session")
        raise RuntimeError("Det gick inte att skicka e-post") from exc
    except SMTPException as exc:
        logger.exception("SMTP error when sending to %s", to_email)
        raise RuntimeError("Det gick inte att skicka e-post") from exc
    except OSError as exc:
        logger.exception("Connection error to email server")
        raise RuntimeError("Det gick inte att ansluta till e-postservern") from exc


def send_creation_email(to_email: str, link: str) -> None:
    """Send a password creation link via SMTP."""

    html_content = f"""
        <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.5;'>
                <p>Hej,</p>
                <p>Skapa ditt konto genom att besöka denna länk:</p>
                <p><a href="{link}">{link}</a></p>
                <p>Om du inte begärde detta e-postmeddelande kan du ignorera det.</p>
            </body>
        </html>
        """

    _send_email(to_email, "Skapa ditt konto", html_content, "Creation")


def send_support_email(personnummer: str) -> None:
    """Notify support that a user requested a password reset."""

    normalized_pnr = functions.normalize_personnummer(personnummer)
    support_email = os.getenv("support_email", "support@utbildningsintyg.se")
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""
        <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.5;'>
                <p>Hej support,</p>
                <p>En användare har begärt återställning av sitt lösenord.</p>
                <p><strong>Personnummer:</strong> {normalized_pnr}</p>
                <p>Begäran registrerades {timestamp} (UTC).</p>
            </body>
        </html>
        """

    _send_email(support_email, "Återställning av lösenord begärd", html_content, "Support")

@app.context_processor
def inject_flags():
    """Expose flags indicating debug mode to Jinja templates."""
    # return {"IS_DEV": current_app.debug}  # funkar också
    return {"IS_DEV": app.debug}



def save_pdf_for_user(pnr: str, file_storage) -> str:
    """Spara PDF i uploads/<hash(pnr)>/ och returnera relativ sökväg."""
    logger.debug("Saving PDF for personnummer %s", pnr)
    if file_storage.filename == '':
        logger.error("No file selected for upload")
        raise ValueError("Ingen fil vald.")

    # Enkel MIME-kontroll + magisk signatur
    mime = file_storage.mimetype or ''
    if mime not in ALLOWED_MIMES:
        logger.error("Disallowed MIME type %s", mime)
        raise ValueError("Endast PDF tillåts.")
    head = file_storage.stream.read(5)
    file_storage.stream.seek(0)
    if head != b'%PDF-':
        logger.error("File does not appear to be valid PDF")
        raise ValueError("Filen verkar inte vara en giltig PDF.")

    pnr_norm = functions.normalize_personnummer(pnr)
    pnr_hash = functions.hash_value(pnr_norm)
    user_dir = os.path.join(app.config['UPLOAD_ROOT'], pnr_hash)
    os.makedirs(user_dir, exist_ok=True)
    logger.debug("User directory for %s is %s", pnr, user_dir)

    base = secure_filename(file_storage.filename)
    # ta bort personnummer från filnamnet om det finns där (t.ex. '199001011234_cv.pdf')
    base = base.replace(pnr_norm, '')
    base = base.lstrip('_- ')  # ta bort eventuella kvarvarande prefix-tecken
    # lägg på timestamp för att undvika krockar
    filename = f"{int(time.time())}_{base}"
    abs_path = os.path.join(user_dir, filename)
    file_storage.save(abs_path)
    logger.info("Saved PDF for %s to %s", pnr, abs_path)

    # relativ sökväg från projektroten
    rel_path = os.path.relpath(abs_path, APP_ROOT).replace('\\', '/')
    return rel_path

@app.route('/robots.txt')
def robots_txt():
    """Serve robots.txt to disallow all crawlers."""
    return send_from_directory(app.static_folder, 'robots.txt', mimetype='text/plain')

@app.route('/create_user/<pnr_hash>', methods=['POST', 'GET'])
def create_user(pnr_hash):
    """Allow a pending user to set a password and activate the account."""
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

@app.route('/', methods=['GET'])
def home():
    """Render the landing page."""
    print("Rendering home page")
    logger.debug("Rendering home page")
    return render_template('index.html')



@app.route('/license', methods=['GET'])
def license():
    """Render the license information page."""
    logger.debug("Rendering license page")
    return render_template('license.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate users using personnummer and password."""
    if request.method == 'POST':
        action = request.form.get('action', 'login')
        personnummer_input = request.form.get('personnummer', '')

        if action == 'forgot-password':
            try:
                send_support_email(personnummer_input)
            except ValueError as exc:
                logger.warning("Invalid personal identity number for password reset: %s", personnummer_input)
                return render_template('user_login.html', error=str(exc))
            except RuntimeError as exc:
                logger.error("Failed to notify support about password reset request")
                return render_template('user_login.html', error=str(exc))

            logger.info("Support notified about password reset for %s", personnummer_input)
            return render_template(
                'user_login.html',
                message='Supporten har informerats om din begäran om återställning.',
            )

        try:
            personnummer = functions.normalize_personnummer(personnummer_input)
        except ValueError as exc:
            logger.warning("Invalid personnummer during login: %s", personnummer_input)
            return render_template('user_login.html', error=str(exc)), 400

        password = request.form.get('password', '')
        logger.debug("Login attempt for %s", personnummer)
        if functions.check_personnummer_password(personnummer, password):
            session['user_logged_in'] = True
            session['personnummer'] = functions.hash_value(personnummer)
            logger.info("User %s logged in", personnummer)
            return redirect('/dashboard')

        logger.warning("Invalid login for %s", personnummer)
        return (
            render_template('user_login.html', error='Ogiltiga inloggningsuppgifter'),
            401,
        )
    logger.debug("Rendering login page")
    return render_template('user_login.html')


@app.route('/dashboard', methods=['GET'])
def dashboard():
    """Visa alla PDF:er för den inloggade användaren."""
    if not session.get('user_logged_in'):
        logger.debug("Unauthenticated access to dashboard")
        return redirect('/login')
    pnr_hash = session.get('personnummer')
    user_dir = os.path.join(app.config['UPLOAD_ROOT'], pnr_hash)
    pdfs = []
    if os.path.isdir(user_dir):
        pdfs = [f for f in os.listdir(user_dir) if f.lower().endswith('.pdf')]
    logger.debug("Dashboard for %s shows %d pdfs", pnr_hash, len(pdfs))
    return render_template('dashboard.html', pdfs=pdfs)


@app.route('/my_pdfs/<path:filename>')
def download_pdf(filename):
    """Serve a stored PDF for the logged-in user.

    If the query parameter ``download`` is set to ``0`` the PDF will be
    displayed inline in the browser instead of being downloaded.
    """
    if not session.get('user_logged_in'):
        logger.debug("Unauthenticated download attempt for %s", filename)
        return redirect('/login')
    pnr_hash = session.get('personnummer')
    user_dir = os.path.join(app.config['UPLOAD_ROOT'], pnr_hash)
    as_attachment = request.args.get('download', '1') != '0'
    logger.info(
        "User %s retrieving %s (as_attachment=%s)", pnr_hash, filename, as_attachment
    )
    return send_from_directory(user_dir, filename, as_attachment=as_attachment)


@app.route('/view_pdf/<path:filename>')
def view_pdf(filename):
    """Render a page displaying the specified PDF inline."""
    if not session.get('user_logged_in'):
        logger.debug("Unauthenticated view attempt for %s", filename)
        return redirect('/login')
    pnr_hash = session.get('personnummer')
    logger.info("User %s viewing %s", pnr_hash, filename)
    pdf_url = url_for('download_pdf', filename=filename, download=0)
    return render_template('view_pdf.html', filename=filename, pdf_url=pdf_url)

@app.route('/admin', methods=['POST', 'GET'])
def admin():
    """Admin dashboard for uploading certificates and creating users."""
    if request.method == 'POST':
        if session.get('admin_logged_in'):
            try:
                email = request.form['email']
                username = request.form['username']
                personnummer = functions.normalize_personnummer(request.form['personnummer'])
                pdf_files = request.files.getlist('pdf')

                if not pdf_files:
                    logger.warning("Admin upload without PDF")
                    return jsonify({'status': 'error', 'message': 'PDF-fil saknas'}), 400

                # Kontrollera om användaren redan finns (via personnummer eller e-post)
                user_exists = functions.get_user_info(personnummer) or functions.check_user_exists(email)

                # spara filerna i mapp per personnummer
                pdf_paths = [save_pdf_for_user(personnummer, f) for f in pdf_files]

                # Om användaren redan finns ska endast PDF:erna sparas
                if user_exists:
                    logger.info("PDFs uploaded for existing user %s", personnummer)
                    return jsonify(
                        {
                            'status': 'success',
                            'message': 'PDF:er uppladdade för befintlig användare',
                        }
                    )

                if functions.admin_create_user(email, username, personnummer, ';'.join(pdf_paths)):
                    pnr_hash = functions.hash_value(personnummer)
                    link = url_for('create_user', pnr_hash=pnr_hash, _external=True)
                    # Skicka e-post med länken för att skapa lösenord
                    try:
                        send_creation_email(email, link)
                    except RuntimeError as e:
                        logger.error("Failed to send creation email to %s", email)
                        return (
                            jsonify({
                                'status': 'error',
                                'message': str(e),
                            }),
                            500,
                        )
                    logger.info("Admin created user %s", personnummer)
                    return jsonify(
                        {
                            'status': 'success',
                            'message': 'Användare skapad',
                            'link': link,
                        }
                    )
                else:
                    logger.warning("Attempt to create existing user %s", personnummer)
                    return redirect('/error')
            except ValueError as ve:
                logger.error("Value error during admin upload: %s", ve)
                return redirect('/error')
            except Exception as e:
                logger.error("Server error during admin upload, %s", e)
                return (
                    jsonify({
                        'status': 'error',
                        'message': 'Serverfel',
                    }),
                    500,
                )
        else:
            logger.warning("Unauthorized admin POST")
            return redirect('/login_admin')
    # GET
    if not session.get('admin_logged_in'):
        logger.warning("Unauthorized admin GET")
        return redirect('/login_admin')
    logger.debug("Rendering admin page")
    return render_template('admin.html')


@app.route('/admin/reset-user', methods=['GET', 'POST'])
def admin_reset_user():
    """Allow an admin to move a user back to pending for password reset."""

    if not session.get('admin_logged_in'):
        logger.warning("Unauthorized admin reset access")
        return redirect('/login_admin')

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        personnummer_input = request.form.get('personnummer', '').strip()

        if not email or not personnummer_input:
            logger.warning("Missing email or personnummer in admin reset request")
            return render_template(
                'admin_reset_user.html',
                error='Både e-postadress och personnummer måste anges.',
            )

        upload_root = current_app.config.get('UPLOAD_ROOT', UPLOAD_ROOT)

        try:
            reset_result = functions.reset_user_to_pending(email, personnummer_input, upload_root)
            link = url_for('create_user', pnr_hash=reset_result['personnummer_hash'], _external=True)
            send_creation_email(email, link)
        except ValueError as exc:
            logger.warning("Could not reset user %s: %s", personnummer_input, exc)
            return render_template('admin_reset_user.html', error=str(exc))
        except RuntimeError as exc:
            logger.exception("Error during admin password reset for %s", personnummer_input)
            return render_template('admin_reset_user.html', error=str(exc))

        logger.info("Admin reset user %s and sent new invitation", reset_result['personnummer_hash'])
        message = f"En återställningslänk har skickats till {email}."
        return render_template(
            'admin_reset_user.html',
            message=message,
            username=reset_result.get('username'),
        )

    return render_template('admin_reset_user.html')


@app.route('/verify_certificate/<personnummer>', methods=['GET'])
def verify_certificate_route(personnummer):
    """Allow an admin to verify whether a user's certificate is confirmed.

    Uses a cached lookup to avoid repeated database queries for the same
    ``personnummer``. Returns a JSON response indicating the verification
    status. If the certificate isn't verified, an informative message is sent
    back to the administrator.
    """
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
    """Intentionally raise an error to test the 500 page."""
    # This will cause a 500 Internal Server Error
    raise Exception("Testing 500 error page")

@app.route('/login_admin', methods=['POST', 'GET'])
def login_admin():
    """Authenticate an administrator for access to the admin panel."""
    if request.method == 'POST':

        admin_password = os.getenv('admin_password')
        admin_username = os.getenv('admin_username')
        if request.form['username'] == admin_username and request.form['password'] == admin_password:
            session['admin_logged_in'] = True
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
    """Logga ut både admin och användare."""
    logger.info("Logging out user and admin")
    session.pop('user_logged_in', None)
    session.pop('admin_logged_in', None)
    session.pop('personnummer', None)
    return redirect('/')

@app.errorhandler(500)
def internal_server_error(_):
    logger.error("500 Internal Server Error: %s", request.path)
    """Visa en användarvänlig 500-sida när ett serverfel inträffar."""
    return render_template('500.html', time=time.time()), 500


@app.errorhandler(409)
def conflict_error(_):
    """Visa en användarvänlig 409-sida vid konflikt."""
    logger.error("409 Conflict: %s", request.path)
    return render_template('409.html'), 409

@app.errorhandler(404)
def page_not_found(_):
    """Visa en användarvänlig 404-sida när en sida saknas."""
    logger.warning("Page not found: %s", request.path)
    return render_template('404.html'), 404

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a POSIX timestamp for display in templates."""
    import datetime
    return datetime.datetime.fromtimestamp(value).strftime(format)

if __name__ == '__main__':
    logger.critical("Starting app from app.py, Debug is enabled")
    app.run(
        debug=True,
        host='0.0.0.0',
        port=int(os.getenv('PORT', 80)),
    )
