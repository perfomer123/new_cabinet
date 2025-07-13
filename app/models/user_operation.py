from app import db
from datetime import datetime

class UserOperation(db.Model):
    __tablename__ = 'user_operations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    operation_type = db.Column(db.String(50), nullable=False)  # "sale" или "consignment"
    product_id = db.Column(db.Integer, nullable=False)  # ID товара
    amount = db.Column(db.Float, nullable=False)  # Сумма операции
    date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False, default='pending')  # pending, confirmed, cancelled

    user = db.relationship('User', backref=db.backref('operations', lazy=True))

    def __repr__(self):
        return f'<UserOperation {self.id} - {self.operation_type} - Amount: {self.amount}>' 