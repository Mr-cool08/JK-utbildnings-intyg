import logging
from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    session,
    redirect,
    send_from_directory,
)
from smtplib import SMTP, SMTPAuthenticationError, SMTPException
import functions
from functions import normalize_personnummer, hash_value
import os
import time
from werkzeug.utils import secure_filename
from dotenv import load_dotenv


logname = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'app.log')
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    filename=logname,
    filemode='a',
)
logger = logging.getLogger(__name__)

APP_ROOT = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(APP_ROOT, 'uploads')
ALLOWED_MIMES = {'application/pdf'}


def create_app() -> Flask:
    """Create and configure the Flask application."""
    logger.debug("Loading environment variables and initializing database")
    load_dotenv()
    functions.create_database()
    app = Flask(__name__)
    app.secret_key = os.getenv('secret_key')
    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    app.config['UPLOAD_ROOT'] = UPLOAD_ROOT
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB, justera vid behov
    logger.debug("Application created with upload root %s", UPLOAD_ROOT)
    return app


app = create_app()


def send_creation_email(to_email: str, link: str) -> None:
    """Send a password creation link to ``to_email`` using SMTP settings.

    The SMTP configuration (server, port, user and password) is read from
    environment variables. The email is sent from the address specified by
    ``smtp_user``.
    """
    smtp_server = os.getenv("smtp_server")
    smtp_port = int(os.getenv("smtp_port", "587"))
    smtp_user = os.getenv("smtp_user")
    smtp_password = os.getenv("smtp_password")

    if not (smtp_server and smtp_user):
        logger.warning("SMTP configuration missing; skipping email to %s", to_email)
        return

    message = (
        "Subject: Create your account\n\n"
        f"Please create your password using the link below:\n{link}\n"
    )

    try:
        logger.debug(
            "Sending creation email via %s:%s to %s", smtp_server, smtp_port, to_email
        )
        with SMTP(smtp_server, smtp_port) as smtp:
            smtp.starttls()
            if smtp_password:
                smtp.login(smtp_user, smtp_password)
            smtp.sendmail(smtp_user, to_email, message)
        logger.info("Creation email sent to %s", to_email)
    except SMTPAuthenticationError as exc:
        logger.exception("SMTP authentication failed for user %s", smtp_user)
        raise RuntimeError("SMTP login failed") from exc
    except SMTPException as exc:
        logger.exception("SMTP error sending mail to %s", to_email)
        raise RuntimeError("Failed to send email") from exc

@app.context_processor
def inject_flags():
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

    pnr_norm = normalize_personnummer(pnr)
    pnr_hash = hash_value(pnr_norm)
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

@app.route('/create_user/<pnr_hash>', methods=['POST', 'GET'])
def create_user(pnr_hash):
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
            return "Error: User not found"

@app.route('/', methods=['GET'])
def home():
    logger.debug("Rendering home page")
    return render_template('index.html')


@app.route('/license', methods=['GET'])
def license():
    logger.debug("Rendering license page")
    return render_template('license.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        personnummer = normalize_personnummer(request.form['personnummer'])
        password = request.form['password']
        logger.debug("Login attempt for %s", personnummer)
        if functions.check_personnummer_password(personnummer, password):
            session['user_logged_in'] = True
            session['personnummer'] = hash_value(personnummer)
            logger.info("User %s logged in", personnummer)
            return redirect('/dashboard')
        else:
            logger.warning("Invalid login for %s", personnummer)
            return (
                render_template('user_login.html', error='Invalid credentials'),
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
    if not session.get('user_logged_in'):
        logger.debug("Unauthenticated download attempt for %s", filename)
        return redirect('/login')
    pnr_hash = session.get('personnummer')
    user_dir = os.path.join(app.config['UPLOAD_ROOT'], pnr_hash)
    logger.info("User %s downloading %s", pnr_hash, filename)
    return send_from_directory(user_dir, filename, as_attachment=True)

@app.route('/admin', methods=['POST', 'GET'])
def admin():
    if request.method == 'POST':
        if session.get('admin_logged_in'):
            try:
                email = request.form['email']
                username = request.form['username']
                personnummer = normalize_personnummer(request.form['personnummer'])
                pdf_file = request.files.get('pdf')

                if not pdf_file:
                    logger.warning("Admin upload without PDF")
                    return jsonify({'status': 'error', 'message': 'PDF-fil saknas'}), 400

                # spara filen i mapp per personnummer
                pdf_path = save_pdf_for_user(personnummer, pdf_file)

                # Om användaren redan finns ska endast PDF:en sparas
                if functions.get_user_info(personnummer):
                    logger.info("PDF uploaded for existing user %s", personnummer)
                    return jsonify(
                        {
                            'status': 'success',
                            'message': 'PDF uploaded for existing user',
                        }
                    )

                if functions.admin_create_user(email, username, personnummer, pdf_path):
                    link = f"/create_user/{hash_value(personnummer)}"
                    # Skicka e-post med länken för att skapa lösenord
                    try:
                        send_creation_email(email, link)
                    except RuntimeError as e:
                        logger.error("Failed to send creation email to %s", email)
                        return redirect('/error')
                    logger.info("Admin created user %s", personnummer)
                    return jsonify(
                        {
                            'status': 'success',
                            'message': 'User created successfully',
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
                return redirect('/error')
        else:
            logger.warning("Unauthorized admin POST")
            return redirect('/login_admin')
    # GET
    if not session.get('admin_logged_in'):
        logger.warning("Unauthorized admin GET")
        return redirect('/login_admin')
    logger.debug("Rendering admin page")
    return render_template('admin.html')
@app.route("/error")
def error():
    # This will cause a 500 Internal Server Error
    raise Exception("Testing 500 error page")

@app.route('/login_admin', methods=['POST', 'GET'])
def login_admin():
    if request.method == 'POST':

        admin_password = os.getenv('admin_password')
        admin_username = os.getenv('admin_username')
        if request.form['username'] == admin_username and request.form['password'] == admin_password:
            session['admin_logged_in'] = True
            logger.info("Admin %s logged in", admin_username)
            return redirect('/admin')
        else:
            logger.warning("Invalid admin login attempt for %s", request.form['username'])
            return jsonify({'status': 'error', 'message': 'Invalid credentials'})
    elif request.method == 'GET':
        logger.debug("Rendering admin login page")
        return render_template('admin_login.html')
    else:
        logger.warning("Invalid request method %s to login_admin", request.method)
        return jsonify({'status': 'error', 'message': 'Invalid request method', 'method': request.method})


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
    """Visa en användarvänlig 500-sida när ett serverfel inträffar."""
    return render_template('500.html', time=time.time()), 500


@app.errorhandler(409)
def conflict_error(_):
    """Visa en användarvänlig 409-sida vid konflikt."""
    logger.warning("409 Conflict: %s", request.path)
    return render_template('409.html'), 409

@app.errorhandler(404)
def page_not_found(_):
    """Visa en användarvänlig 404-sida när en sida saknas."""
    logger.warning("Page not found: %s", request.path)
    return render_template('404.html'), 404

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    import datetime
    return datetime.datetime.fromtimestamp(value).strftime(format)

if __name__ == '__main__':
    if os.getenv('FLASK_ENV') == 'development':
        functions.create_database()
        functions.create_test_user()  # Skapa en testanvändare vid start
        logger.info("Running in development mode")
    else:
        logger.info("Running in production mode")
    app.run(
        debug=os.getenv('FLASK_ENV') == 'development',
        host='0.0.0.0',
        port=int(os.getenv('PORT', 80)),
    )
