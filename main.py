from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    session,
    redirect,
    send_from_directory,
    g,
)
from smtplib import SMTP
import functions
from functions import normalize_personnummer, hash_value
import os
import time
import logging
import uuid
import sqlite3
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

try:
    from flask_cors import CORS
except Exception:  # pragma: no cover - fallback when package missing
    CORS = None

try:
    from flask_talisman import Talisman
except Exception:  # pragma: no cover - fallback when package missing
    class Talisman:  # type: ignore
        def __init__(self, app, *args, **kwargs):
            pass


APP_ROOT = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(APP_ROOT, 'uploads')
ALLOWED_MIMES = {'application/pdf'}


def create_app() -> Flask:
    """Create and configure the Flask application."""
    load_dotenv()
    functions.create_database()
    app = Flask(__name__)

    # Debug configuration
    debug_flag = os.getenv('FLASK_DEBUG')
    app.debug = debug_flag.lower() in {'1', 'true', 'yes'} if debug_flag else False

    # Secret key and uploads
    app.secret_key = os.getenv('SECRET_KEY', 'change-me')
    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    app.config['UPLOAD_ROOT'] = UPLOAD_ROOT
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB, justera vid behov

    # Secure cookies in production
    app.config.update(
        SESSION_COOKIE_SECURE=not app.debug,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )

    # Logging configuration
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s [%(request_id)s] %(message)s'
    )
    handler.setFormatter(formatter)

    class RequestIDFilter(logging.Filter):
        def filter(self, record):
            record.request_id = getattr(g, 'request_id', '-')
            return True

    handler.addFilter(RequestIDFilter())
    app.logger.addHandler(handler)
    app.logger.setLevel(log_level)
    app.logger.propagate = False

    # Security headers (Talisman if available)
    Talisman(
        app,
        content_security_policy={'default-src': "'self'"},
        force_https=False,
    )

    # CORS
    origins = os.getenv('ALLOWED_ORIGINS')
    if origins:
        origin_list = [o.strip() for o in origins.split(',') if o.strip()]
        if CORS:
            CORS(app, origins=origin_list)
        else:
            @app.after_request
            def _cors_headers(resp):  # pragma: no cover - simple fallback
                origin = request.headers.get('Origin')
                if origin in origin_list:
                    resp.headers['Access-Control-Allow-Origin'] = origin
                return resp
    elif app.debug and CORS:
        CORS(app)

    return app


app = create_app()

@app.context_processor
def inject_flags():
    return {"IS_DEV": app.debug}


def wants_json_response() -> bool:
    if request.path.startswith("/api/"):
        return True
    return request.accept_mimetypes.best == "application/json"


@app.before_request
def assign_request_id():
    g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))


@app.after_request
def add_request_id(response):
    response.headers["X-Request-ID"] = g.request_id
    # Security headers
    response.headers.setdefault(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
    )
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    return response
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


@app.get('/healthz')
def healthz():
    return jsonify({'status': 'ok'})


@app.get('/readiness')
def readiness():
    checks = {}
    ok = True
    # storage path
    path = app.config.get('UPLOAD_ROOT')
    try:
        os.makedirs(path, exist_ok=True)
        if os.access(path, os.W_OK):
            checks['storage'] = 'ok'
        else:
            checks['storage'] = 'not_writable'
            ok = False
    except Exception as e:
        checks['storage'] = str(e)
        ok = False
    # database
    try:
        conn = sqlite3.connect('database.db')
        conn.execute('SELECT 1')
        conn.close()
        checks['database'] = 'ok'
    except Exception as e:
        checks['database'] = str(e)
        ok = False
    status = 'ok' if ok else 'error'
    code = 200 if ok else 503
    return jsonify({'status': status, 'checks': checks}), code

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
def handle_400(e):
    if wants_json_response():
        return (
            jsonify(
                {
                    'type': 'bad_request',
                    'message': 'Bad Request',
                    'status': 400,
                    'request_id': g.request_id,
                }
            ),
            400,
        )
    return "Bad Request", 400


@app.errorhandler(404)
def handle_404(e):
    if wants_json_response():
        return (
            jsonify(
                {
                    'type': 'not_found',
                    'message': 'Not Found',
                    'status': 404,
                    'request_id': g.request_id,
                }
            ),
            404,
        )
    return render_template('404.html'), 404


@app.errorhandler(405)
def handle_405(e):
    if wants_json_response():
        return (
            jsonify(
                {
                    'type': 'method_not_allowed',
                    'message': 'Method Not Allowed',
                    'status': 405,
                    'request_id': g.request_id,
                }
            ),
            405,
        )
    return "Method Not Allowed", 405


@app.errorhandler(Exception)
def handle_500(e):
    app.logger.exception("Unhandled exception")
    if wants_json_response():
        return (
            jsonify(
                {
                    'type': 'internal_error',
                    'message': 'Internal Server Error',
                    'status': 500,
                    'request_id': g.request_id,
                }
            ),
            500,
        )
    return "Internal Server Error", 500

if __name__ == '__main__':
    if app.debug:
        functions.create_database()
        functions.create_test_user()  # Skapa en testanvändare vid start
        print("Running in development mode")
    else:
        print("Running in production mode")
    app.run(
        debug=app.debug,
        host='0.0.0.0',
        port=int(os.getenv('PORT', 8000)),
    )
