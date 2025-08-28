from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
import os

app = Flask(__name__)

# Укажите абсолютный путь к базе данных
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance/users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    tariff_id = db.Column(db.Integer, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    extension_days = db.Column(db.Integer, nullable=False)
    payment_date = db.Column(db.DateTime, default=datetime.utcnow)
    key = db.Column(db.String(150), nullable=False)
    payment_id = db.Column(db.String(150), nullable=False)  # Новое поле для payment_id

if __name__ == '__main__':
    app.run(debug=True)
