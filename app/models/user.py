from app import db
from datetime import datetime
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(150), nullable=True)
    role = db.Column(db.String(50), nullable=False)
    reset_token = db.Column(db.String(150), nullable=True)
    tariff_id = db.Column(db.Integer, db.ForeignKey('tariff.id'), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(250), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    verification_code = db.Column(db.String(10), nullable=True)
    code_time = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    balance = db.Column(db.Float, default=0.0)
    platform_id = db.Column(db.String(50), nullable=True)
    
    def __repr__(self):
        return f'<User {self.username}>' 