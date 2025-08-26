import logging
import os
import sqlite3
import time
import uuid

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
)
from flask_cors import CORS
from flask_talisman import Talisman
from smtplib import SMTP
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

import functions
from functions import hash_value, normalize_personnummer


APP_ROOT = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(APP_ROOT, 'uploads')
ALLOWED_MIMES = {'application/pdf'}


def create_app() -> Flask:
    """Create and configure the Flask application."""
    load_dotenv()
    functions.create_database()

    app = Flask(__name__)

    debug = os.getenv("FLASK_DEBUG", "0") in {"1", "true", "True"}
    app.config["DEBUG"] = debug

    app.secret_key = os.getenv("SECRET_KEY", os.getenv("secret_key", ""))
    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    app.config["UPLOAD_ROOT"] = UPLOAD_ROOT
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

    app.config.update(
        SESSION_COOKIE_SECURE=not debug,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    # Logging configuration
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(request_id)s] %(message)s"
    )
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.handlers = []
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    class RequestIDFilter(logging.Filter):
        def filter(self, record):
            record.request_id = getattr(g, "request_id", "-")
            return True

    root_logger.addFilter(RequestIDFilter())

    # Security headers
    csp = {"default-src": "'self'"}
    Talisman(app, content_security_policy=csp, force_https=False)

    # Optional CORS
    allowed = os.getenv("ALLOWED_ORIGINS")
    if allowed:
        origins = [o.strip() for o in allowed.split(",") if o.strip()]
        CORS(app, origins=origins)

    return app


app = create_app()


@app.before_request
def set_request_id():
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    g.request_id = req_id


@app.after_request
def add_request_id(response):
    response.headers["X-Request-ID"] = g.get("request_id", "")
    return response

@app.context_processor
def inject_flags():
    return {"IS_DEV": app.debug}


def wants_json_response() -> bool:
    return (
        request.path.startswith("/api/")
        or request.accept_mimetypes.best == "application/json"
        or request.is_json
    )


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.route("/readiness")
def readiness():
    checks = {}
    upload_root = app.config.get("UPLOAD_ROOT")
    checks["filesystem"] = os.path.isdir(upload_root) and os.access(
        upload_root, os.W_OK
    )

    try:
        conn = sqlite3.connect("database.db")
        conn.execute("SELECT 1")
        conn.close()
        checks["database"] = True
    except Exception:
        checks["database"] = False

    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        try:
            import redis

            redis.from_url(redis_url).ping()
            checks["redis"] = True
        except Exception:
            checks["redis"] = False

    status_code = 200 if all(checks.values()) else 503
    status = "ok" if status_code == 200 else "error"
    result = {"status": status, "checks": checks}
    if status_code != 200:
        result["reason"] = ",".join([k for k, v in checks.items() if not v])
    return jsonify(result), status_code
def save_pdf_for_user(pnr: str, file_storage) -> str:
    """Spara PDF i uploads/<hash(pnr)>/ och returnera relativ sökväg."""
    if file_storage.filename == '':
        raise ValueError("Ingen fil vald.")

    # Enkel MIME-kontroll + magisk signatur
    mime = file_storage.mimetype or ''
    if mime not in ALLOWED_MIMES:
        raise ValueError("Endast PDF tillåts.")
    head = file_storage.stream.read(5)
    file_storage.stream.seek(0)
    if head != b'%PDF-':
        raise ValueError("Filen verkar inte vara en giltig PDF.")

    pnr_norm = normalize_personnummer(pnr)
    pnr_hash = hash_value(pnr_norm)
    user_dir = os.path.join(app.config['UPLOAD_ROOT'], pnr_hash)
    os.makedirs(user_dir, exist_ok=True)

    base = secure_filename(file_storage.filename)
    # ta bort personnummer från filnamnet om det finns där (t.ex. '199001011234_cv.pdf')
    base = base.replace(pnr_norm, '')
    base = base.lstrip('_- ')  # ta bort eventuella kvarvarande prefix-tecken
    # lägg på timestamp för att undvika krockar
    filename = f"{int(time.time())}_{base}"
    abs_path = os.path.join(user_dir, filename)
    file_storage.save(abs_path)

    # relativ sökväg från projektroten
    rel_path = os.path.relpath(abs_path, APP_ROOT).replace('\\', '/')
    return rel_path

@app.route('/create_user/<pnr_hash>', methods=['POST', 'GET'])
def create_user(pnr_hash):
    if request.method == 'POST':
        password = request.form['password']
        print(f"Skapar användare med hash: {pnr_hash} och lösenord: {password}")
        functions.user_create_user(password, pnr_hash)
        return redirect('/login')
    elif request.method == 'GET':
        if functions.check_pending_user_hash(pnr_hash):
            return render_template('create_user.html')
        else:
            return "Error: User not found"

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')


@app.route('/license', methods=['GET'])
def license():
    return render_template('license.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        personnummer = normalize_personnummer(request.form['personnummer'])
        password = request.form['password']
        if functions.check_personnummer_password(personnummer, password):
            session['user_logged_in'] = True
            session['personnummer'] = hash_value(personnummer)
            return redirect('/dashboard')
        else:
            return (
                render_template('user_login.html', error='Invalid credentials'),
                401,
            )
    return render_template('user_login.html')


@app.route('/dashboard', methods=['GET'])
def dashboard():
    """Visa alla PDF:er för den inloggade användaren."""
    if not session.get('user_logged_in'):
        return redirect('/login')
    pnr_hash = session.get('personnummer')
    user_dir = os.path.join(app.config['UPLOAD_ROOT'], pnr_hash)
    pdfs = []
    if os.path.isdir(user_dir):
        pdfs = [f for f in os.listdir(user_dir) if f.lower().endswith('.pdf')]
    return render_template('dashboard.html', pdfs=pdfs)


@app.route('/my_pdfs/<path:filename>')
def download_pdf(filename):
    if not session.get('user_logged_in'):
        return redirect('/login')
    pnr_hash = session.get('personnummer')
    user_dir = os.path.join(app.config['UPLOAD_ROOT'], pnr_hash)
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
                    return jsonify({'status': 'error', 'message': 'PDF-fil saknas'}), 400

                # spara filen i mapp per personnummer
                pdf_path = save_pdf_for_user(personnummer, pdf_file)

                # Om användaren redan finns ska endast PDF:en sparas
                if functions.get_user_info(personnummer):
                    return jsonify(
                        {
                            'status': 'success',
                            'message': 'PDF uploaded for existing user',
                        }
                    )

                if functions.admin_create_user(email, username, personnummer, pdf_path):
                    link = f"/create_user/{hash_value(personnummer)}"
                    return jsonify(
                        {
                            'status': 'success',
                            'message': 'User created successfully',
                            'link': link,
                        }
                    )
                else:
                    return jsonify({'status': 'error', 'message': 'User already exists'}), 409
            except ValueError as ve:
                return jsonify({'status': 'error', 'message': str(ve)}), 400
            except Exception as e:
                # logga e om du vill
                return jsonify({'status': 'error', 'message': 'Serverfel vid uppladdning'}), 500
        else:
            return redirect('/login_admin')
    # GET
    if not session.get('admin_logged_in'):
        return redirect('/login_admin')
    return render_template('admin.html')


@app.route('/login_admin', methods=['POST', 'GET'])
def login_admin():
    if request.method == 'POST':
        
        admin_password = os.getenv('admin_password')
        admin_username = os.getenv('admin_username')
        if request.form['username'] == admin_username and request.form['password'] == admin_password:
            session['admin_logged_in'] = True
            return redirect('/admin')
        else:
            return jsonify({'status': 'error', 'message': 'Invalid credentials'})
    elif request.method == 'GET':
        return render_template('admin_login.html')
    else:
        return jsonify({'status': 'error', 'message': 'Invalid request method', 'method': request.method})


@app.route('/logout')
def logout():
    """Logga ut både admin och användare."""
    session.pop('user_logged_in', None)
    session.pop('admin_logged_in', None)
    session.pop('personnummer', None)
    return redirect('/')


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
def handle_client_errors(e):
    code = getattr(e, "code", 500)
    if wants_json_response():
        return (
            jsonify(
                {
                    "type": e.__class__.__name__,
                    "message": getattr(e, "description", str(e)),
                    "status": code,
                    "request_id": g.get("request_id"),
                }
            ),
            code,
        )
    if code == 404:
        return render_template("404.html"), 404
    return str(e), code


@app.errorhandler(500)
def handle_server_error(e):
    app.logger.exception("Unhandled exception")
    if wants_json_response():
        return (
            jsonify(
                {
                    "type": e.__class__.__name__,
                    "message": "Internal server error",
                    "status": 500,
                    "request_id": g.get("request_id"),
                }
            ),
            500,
        )
    return "Internal Server Error", 500

if __name__ == '__main__':
    if app.debug:
        functions.create_database()
        functions.create_test_user()
        print("Running in development mode")
    else:
        print("Running in production mode")
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 80)))
