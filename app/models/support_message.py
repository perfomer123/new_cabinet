from app import db
from datetime import datetime

class SupportMessage(db.Model):
    __tablename__ = 'support_message'

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('support_ticket.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    author_type = db.Column(db.String(16), nullable=False)  # 'user' or 'admin'
    text = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    read_by_user = db.Column(db.Boolean, default=False)
    read_by_admin = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'ticket_id': self.ticket_id,
            'author_id': self.author_id,
            'author_type': self.author_type,
            'text': self.text,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
        }
