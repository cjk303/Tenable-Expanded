from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Run(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(128))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    logs = db.Column(db.Text)      # Raw Ansible logs
    results = db.Column(db.JSON)   # Summary of hosts, e.g., {"host1": {"removed_rapid7": True, ...}}
