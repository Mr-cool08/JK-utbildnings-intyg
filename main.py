from flask import (
    Flask,
    g,
    request,
    jsonify,
    render_template,
    session,
    redirect,
    send_from_directory,
)
from smtplib import SMTP
import functions
from functions import normalize_personnummer, hash_value
import logging
import os
import sqlite3
import sys
import time
from uuid import uuid4
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from flask_talisman import Talisman
from flask_cors import CORS


APP_ROOT = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(APP_ROOT, 'uploads')
ALLOWED_MIMES = {'application/pdf'}


class RequestIDFilter(logging.Filter):
    def filter(self, record):
        try:
            record.request_id = g.get('request_id', '-')
        except Exception:
            record.request_id = '-'
        return True


def create_app() -> Flask:
    """Create and configure the Flask application."""
    load_dotenv()
    functions.create_database()
    app = Flask(__name__)

    debug = os.getenv('FLASK_DEBUG', '0') == '1'
    app.debug = debug
    app.secret_key = os.getenv('SECRET_KEY') or os.getenv('secret_key')

    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    app.config['UPLOAD_ROOT'] = UPLOAD_ROOT
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB, justera vid behov
    app.config.update(
        SESSION_COOKIE_SECURE=not debug,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )

    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            '%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s'
        )
    )
    handler.addFilter(RequestIDFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(log_level)

    Talisman(app, content_security_policy={'default-src': "'self'"})

    origins = os.getenv('ALLOWED_ORIGINS')
    if origins:
        origin_list = [o.strip() for o in origins.split(',') if o.strip()]
        CORS(app, origins=origin_list)

    return app


app = create_app()

@app.context_processor
def inject_flags():
    return {"IS_DEV": app.debug}


@app.before_request
def add_request_id():
    req_id = request.headers.get('X-Request-ID', str(uuid4()))
    g.request_id = req_id


@app.after_request
def set_request_id_header(response):
    response.headers['X-Request-ID'] = g.get('request_id', '-')
    return response


def wants_json_response() -> bool:
    if request.path.startswith('/api/'):
        return True
    best = request.accept_mimetypes.best
    return best == 'application/json'
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


@app.route('/healthz')
def healthz():
    return jsonify({'status': 'ok'})


@app.route('/readiness')
def readiness():
    details = {}
    root = app.config['UPLOAD_ROOT']
    if os.path.isdir(root) and os.access(root, os.W_OK):
        details['storage'] = 'ok'
    else:
        details['storage'] = 'not_writable'
    try:
        conn = sqlite3.connect('database.db')
        conn.execute('SELECT 1')
        conn.close()
        details['database'] = 'ok'
    except Exception as exc:
        details['database'] = str(exc)

    ok = all(v == 'ok' for v in details.values())
    status_code = 200 if ok else 503
    return jsonify({'status': 'ok' if ok else 'unavailable', 'details': details}), status_code


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


def _handle_error(err, status_code):
    if wants_json_response() or request.is_json:
        return (
            jsonify(
                {
                    'type': err.__class__.__name__,
                    'message': str(err),
                    'status': status_code,
                    'request_id': g.get('request_id'),
                }
            ),
            status_code,
        )
    if status_code == 404:
        return render_template('404.html'), 404
    return str(err), status_code


@app.errorhandler(400)
def handle_400(err):
    return _handle_error(err, 400)


@app.errorhandler(404)
def handle_404(err):
    return _handle_error(err, 404)


@app.errorhandler(405)
def handle_405(err):
    return _handle_error(err, 405)


@app.errorhandler(Exception)
def handle_exception(err):
    app.logger.exception('Unhandled exception: %s', err)
    return _handle_error(err, 500)

if __name__ == '__main__':
    if app.debug:
        functions.create_test_user()  # Skapa en testanvändare vid start
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=app.debug)
