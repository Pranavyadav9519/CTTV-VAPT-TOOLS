from database.models import db, Scan
from config import config_by_name
from flask import Flask

app = Flask(__name__)
app.config.from_object(config_by_name.get("development"))
db.init_app(app)

with app.app_context():
    scans = Scan.query.all()
    print("Current scans:")
    for s in scans:
        print(
            f"ID: {s.id}, ScanID: {s.scan_id}, Status: {s.status}, Started: {s.started_at}"
        )
