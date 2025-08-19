from flask import Flask, request, jsonify
from smtplib import SMTP
import datetime
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def process_data():
    data = request.json
    # Process the data as needed
    return jsonify({"message": "Data processed successfully", "data": data}), 200

if __name__ == '__main__':
    app.run(debug=True)
