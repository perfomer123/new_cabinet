from app import db

class Tariff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    base_price = db.Column(db.Float, nullable=False)
    partner_initial_payment = db.Column(db.Float, nullable=False)
    manager_initial_payment = db.Column(db.Float, nullable=False)
    supervisor_initial_payment = db.Column(db.Float, nullable=False)
    partner_subscription_percentage = db.Column(db.Float, nullable=False)
    manager_subscription_percentage = db.Column(db.Float, nullable=False)
    supervisor_subscription_percentage = db.Column(db.Float, nullable=False)
    restricted = db.Column(db.Boolean, default=False)  # Поле restricted
    
    def __repr__(self):
        return f'<Tariff {self.name}>' 