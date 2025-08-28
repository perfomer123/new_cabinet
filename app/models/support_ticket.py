from app import db
from datetime import datetime


class SupportTicket(db.Model):
    __tablename__ = 'support_ticket'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user_key_id = db.Column(db.Integer, db.ForeignKey('user_key.id'), nullable=True)

    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)

    status = db.Column(db.String(50), nullable=False, default='open')  # open, in_progress, closed

    key_value = db.Column(db.String(150), nullable=True)
    contact = db.Column(db.String(150), nullable=True)  # email/phone for callback if needed
    source = db.Column(db.String(50), nullable=True, default='app')

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<SupportTicket id={self.id} subject={self.subject!r} status={self.status}>"
