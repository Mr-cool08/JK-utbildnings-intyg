from flask import Flask, request, jsonify, render_template, session, redirect
from smtplib import SMTP
import datetime
import database_handling
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('secret_key')

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/admin', methods=['POST', 'GET'])
def admin():
    if request.method == 'POST':
        if session.get('logged_in'):
                
            email = request.form['email']
            username = request.form['username']
            personsnummer = request.form['personsnummer']
            
            
            
            if database_handling.admin_create_user(email, username, personsnummer, pdf_path):
                return jsonify({'status': 'success', 'message': 'User created successfully'})
            else:
                return jsonify({'status': 'error', 'message': 'User already exists'})
    else:
        if not session.get('logged_in'):
            return redirect('/login_admin')
    if request.method == 'GET':
        
        return render_template('admin.html')


@app.route('/login_admin', methods=['POST', 'GET'])
def login_admin():
    if request.method == 'POST':
        
        admin_password = os.getenv('admin_password')
        admin_username = os.getenv('admin_username')
        if request.form['username'] == admin_username and request.form['password'] == admin_password:
            session['logged_in'] = True
            return redirect('/admin')
        else:
            return jsonify({'status': 'error', 'message': 'Invalid credentials'})
    elif request.method == 'GET':
        return render_template('admin_login.html')
    else:
        return jsonify({'status': 'error', 'message': 'Invalid request method', 'method': request.method})

if __name__ == '__main__':
    database_handling.create_database()
    app.run(debug=True, host='0.0.0.0', port=80)
