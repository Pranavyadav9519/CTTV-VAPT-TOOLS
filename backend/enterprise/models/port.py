"""
Port quickly. Model
"""

from datetime import datetime
from app.extensions import db


class Port(db.Model):
    __tablename__ = "ports"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default="tcp")
    state = db.Column(db.String(20), default="open")
    service_name = db.Column(db.String(50))
    service_version = db.Column(db.String(100))
    banner = db.Column(db.Text)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "port_number": self.port_number,
            "protocol": self.protocol,
            "state": self.state,
            "service_name": self.service_name,
            "service_version": self.service_version,
            "banner": self.banner,
        }
