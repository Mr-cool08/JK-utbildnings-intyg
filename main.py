from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    session,
    redirect,
    send_from_directory,
)
from smtplib import SMTP
import functions
from functions import normalize_personnummer
import os
import time
from werkzeug.utils import secure_filename
from dotenv import load_dotenv



load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('secret_key')
APP_ROOT = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(APP_ROOT, 'uploads')
os.makedirs(UPLOAD_ROOT, exist_ok=True)
app.config['UPLOAD_ROOT'] = UPLOAD_ROOT
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB, justera vid behov
ALLOWED_MIMES = {'application/pdf'}


def save_pdf_for_user(pnr: str, file_storage) -> str:
    """Spara PDF i uploads/<pnr>/ och returnera relativ sökväg (t.ex. 'uploads/199001011234/12345_cv.pdf')."""
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
    user_dir = os.path.join(app.config['UPLOAD_ROOT'], pnr_norm)
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

@app.route('/create_user/<personnummer>', methods=['POST', 'GET'])
def create_user(personnummer):
    pnr_norm = normalize_personnummer(personnummer)
    if request.method == 'POST':
        password = request.form['password']
        print(f"Skapar användare med personnummer: {pnr_norm} och lösenord: {password}")
        functions.user_create_user(password, pnr_norm)
        return redirect('/')
    elif request.method == 'GET':
        if functions.check_pending_user(pnr_norm):
            return render_template('create_user.html', personnummer=pnr_norm)
        else:
            return "Error: User not found"

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        personnummer = normalize_personnummer(request.form['personnummer'])
        password = request.form['password']
        if functions.check_personnummer_password(personnummer, password):
            session['user_logged_in'] = True
            session['personnummer'] = personnummer
            return redirect('/')
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
    pnr = session.get('personnummer')
    try:
        pnr_norm = normalize_personnummer(pnr)
    except Exception:
        return redirect('/login')
    user_dir = os.path.join(app.config['UPLOAD_ROOT'], pnr_norm)
    pdfs = []
    if os.path.isdir(user_dir):
        pdfs = [f for f in os.listdir(user_dir) if f.lower().endswith('.pdf')]
    return render_template('dashboard.html', pdfs=pdfs)


@app.route('/my_pdfs/<path:filename>')
def download_pdf(filename):
    if not session.get('user_logged_in'):
        return redirect('/login')
    pnr = session.get('personnummer')
    try:
        pnr_norm = normalize_personnummer(pnr)
    except Exception:
        return redirect('/login')
    user_dir = os.path.join(app.config['UPLOAD_ROOT'], pnr_norm)
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
                    return jsonify({'status': 'success', 'message': 'User created successfully'})
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

if __name__ == '__main__':
    functions.create_database()
    functions.create_test_user()  # Skapa en testanvändare vid start
    app.run(debug=True, host='0.0.0.0', port=80)
