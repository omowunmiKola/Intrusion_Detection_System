#to run do python3 backend.py on terminal first and go to http://127.0.0.1:5000/api/alerts
#sudo nmap -sS -p 1-100 -D RND:10 localhost (nmap scan)

import json
import sqlite3
from flask import Flask, jsonify,request,g, render_template
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
DATABASE = "IDS_database.db"
#connection = sqlite3.connect('IDS_database.db')

def get_db():
    db = getattr(g, "_database",None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Automatically closes the database connection when the request finishes."""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()
    

def process_logs():
    try:
        with open('alerts.txt', 'r') as file:
            lines = file.readlines()
            if not lines:
                return
            for line in lines:
                alert_data = json.loads(line)
                db = get_db()
                cursor = db.cursor()
                cursor.execute('INSERT INTO "SYN LOGS" (IP_Address, Type, Timestamp) VALUES (?, ?, ?)', (alert_data['attacker_ip'], alert_data['type'], alert_data['timestamp']))

            db.commit()
            with open('alerts.txt', 'w') as file:
                return
    except FileNotFoundError:
        print("No alerts file found yet. Waiting for the C sniffer...")

@app.route('/')
def index():
    return render_template('index.html')        

@app.route('/api/alerts')
def get_alerts():
    process_logs()

    db = get_db()
    cursor = db.cursor()

    cursor.execute('SELECT * FROM "SYN LOGS" ORDER BY Timestamp DESC')
    rows = cursor.fetchall()
    db.close

    data = [dict(row) for row in rows]
    return jsonify(data)

@app.route('/api/reset', methods=['POST'])
def reset_logs():
    db = get_db()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM "SYN LOGS";')
    db.commit()
    db.close()
    return jsonify({"status": "Logs cleared!"})

if __name__ == '__main__':
    app.run(debug=True)


