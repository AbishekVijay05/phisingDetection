from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import json

db = SQLAlchemy()

class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_type = db.Column(db.String(10), nullable=False)  # url, email, sms
    scan_summary = db.Column(db.String(255), nullable=False)  # domain / sender domain / "SMS #id"
    risk_score = db.Column(db.Float, nullable=False, default=0.0)  # 0-100
    verdict = db.Column(db.String(20), nullable=False, default='SAFE')  # SAFE / SUSPICIOUS / PHISHING
    details_json = db.Column(db.Text, nullable=True)  # JSON with layer-wise breakdown
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'scan_summary': self.scan_summary,
            'risk_score': self.risk_score,
            'verdict': self.verdict,
            'details': json.loads(self.details_json) if self.details_json else {},
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<Scan {self.id} [{self.scan_type}] {self.verdict}>'
