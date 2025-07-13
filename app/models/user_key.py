from app import db

class UserKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(50), nullable=True)
    start_date = db.Column(db.String(50), nullable=True)
    end_date = db.Column(db.String(50), nullable=True)
    tariff_id = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f'<UserKey {self.key}>' 