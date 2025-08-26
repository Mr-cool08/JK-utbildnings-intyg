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
import logging
import sys
import uuid
import sqlite3
import functions
from functions import normalize_personnummer, hash_value
import os
import time
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
try:
    from flask_cors import CORS
except Exception:  # pragma: no cover - optional dependency
    def CORS(*args, **kwargs):
        return None

try:
    from flask_talisman import Talisman
except Exception:  # pragma: no cover - optional dependency
    class Talisman:  # type: ignore
        def __init__(self, *args, **kwargs):
            pass


APP_ROOT = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(APP_ROOT, 'uploads')
ALLOWED_MIMES = {'application/pdf'}


class RequestIDFilter(logging.Filter):
    def filter(self, record):
        record.request_id = getattr(g, 'request_id', '-')
        return True


def configure_logging(app: Flask, level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s [%(request_id)s] %(message)s'
    )
    handler.setFormatter(formatter)
    handler.addFilter(RequestIDFilter())
    app.logger.handlers = [handler]
    app.logger.setLevel(level)


def create_app() -> Flask:
    """Create and configure the Flask application."""
    load_dotenv()
    functions.create_database()
    app = Flask(__name__)
    app.secret_key = os.getenv('SECRET_KEY') or os.getenv('secret_key')

    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.config['DEBUG'] = debug
    if not debug:
        app.config.update(
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Lax',
        )

    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    app.config['UPLOAD_ROOT'] = UPLOAD_ROOT
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

    configure_logging(app, os.getenv('LOG_LEVEL', 'INFO').upper())

    allowed_origins = os.getenv('ALLOWED_ORIGINS')
    cors_origins = None
    if allowed_origins:
        cors_origins = [o.strip() for o in allowed_origins.split(',') if o.strip()]
        try:
            CORS(app, origins=cors_origins)
        except Exception:
            pass

    Talisman(app, force_https=False, content_security_policy={"default-src": "'self'"})

    @app.before_request
    def set_request_id():
        g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))

    @app.after_request
    def add_headers(response):
        response.headers['X-Request-ID'] = g.get('request_id', '')
        response.headers.setdefault(
            'Strict-Transport-Security', 'max-age=31536000; includeSubDomains'
        )
        response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Content-Security-Policy', "default-src 'self'")
        if cors_origins:
            origin = request.headers.get('Origin')
            if origin in cors_origins:
                response.headers['Access-Control-Allow-Origin'] = origin
        return response

    return app


app = create_app()

@app.context_processor
def inject_flags():
    return {"IS_DEV": app.debug}
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

@app.route('/healthz')
def healthz():
    return jsonify({'status': 'ok'})


@app.route('/readiness')
def readiness():
    details = {}
    storage = app.config['UPLOAD_ROOT']
    if os.path.isdir(storage) and os.access(storage, os.W_OK):
        details['storage'] = 'ok'
    else:
        details['storage'] = 'unwritable'

    try:
        conn = sqlite3.connect('database.db')
        conn.execute('SELECT 1')
        conn.close()
        details['database'] = 'ok'
    except Exception as e:
        details['database'] = str(e)

    status = 'ok'
    status_code = 200
    if any(v != 'ok' for v in details.values()):
        status = 'fail'
        status_code = 503
    return jsonify({'status': status, 'details': details}), status_code


def wants_json_response() -> bool:
    return (
        request.path.startswith('/api/')
        or request.accept_mimetypes.best == 'application/json'
    )


def json_error_response(error, status_code):
    return (
        jsonify(
            {
                'type': error.__class__.__name__,
                'message': getattr(error, 'description', str(error)),
                'status': status_code,
                'request_id': g.get('request_id'),
            }
        ),
        status_code,
    )


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
def handle_4xx(error):
    code = getattr(error, 'code', 400)
    if wants_json_response():
        return json_error_response(error, code)
    if code == 404:
        return render_template('404.html'), 404
    return str(getattr(error, 'description', error)), code


@app.errorhandler(500)
def handle_500(error):
    app.logger.exception('Unhandled exception: %s', error)
    if wants_json_response():
        return json_error_response(error, 500)
    return 'Internal Server Error', 500


if __name__ == '__main__':
    if app.debug:
        functions.create_test_user()  # Skapa en testanvändare vid start
        print("Running in development mode")
    else:
        print("Running in production mode")
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 80)))
