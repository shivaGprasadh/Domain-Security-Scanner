import datetime
from flask_sqlalchemy import SQLAlchemy
import json

db = SQLAlchemy()

class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    scan_results = db.relationship('ScanResult', backref='domain', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Domain {self.name}>'


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    security_score = db.Column(db.Integer, default=0)
    security_rank = db.Column(db.String(5), default='E')
    ssl_expiry = db.Column(db.String(50), nullable=True)
    ssl_days_remaining = db.Column(db.Integer, nullable=True)
    scan_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    full_report = db.Column(db.Text, nullable=True)  # Storing JSON as text
    
    def __repr__(self):
        return f'<ScanResult for {self.domain.name} at {self.scan_time}>'
    
    def set_full_report(self, report_dict):
        """Store the full report data as JSON string"""
        self.full_report = json.dumps(report_dict)
    
    def get_full_report(self):
        """Retrieve and parse the full report data"""
        if not self.full_report:
            return {"checks": {}, "error": "No report data available"}
            
        try:
            return json.loads(self.full_report)
        except json.JSONDecodeError as e:
            # Handle corrupt JSON data
            import logging
            logging.error(f"Error parsing JSON report for domain {self.domain_id}: {str(e)}")
            return {
                "checks": {},
                "error": "Error parsing report data",
                "message": "The scan report contains invalid data. Try rescanning the domain."
            }


class ScheduledScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    last_full_scan = db.Column(db.DateTime, nullable=True)
    next_scheduled_scan = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<ScheduledScan last={self.last_full_scan}, next={self.next_scheduled_scan}>'