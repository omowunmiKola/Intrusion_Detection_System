import json
import sqlite3
from flask import Flask, jsonify,request,g

app = Flask(__name__)
DATABASE = "IDS_datbase.db"
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
                cursor = db.cursor
                cursor.execute("INSERT INTO table_name (IP_Address, Type, Timestamp) VALUES (?, ?, ?)", (IP_Address, Type, Timestamp))

            db.commit
