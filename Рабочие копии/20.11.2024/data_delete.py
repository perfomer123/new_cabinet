# data_delete.py

import os
from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Настройки приложения и базы данных
app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'instance/users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация SQLAlchemy
db = SQLAlchemy(app)

# Определение модели UserOperation
class UserOperation(db.Model):
    __tablename__ = 'user_operations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    operation_type = db.Column(db.String(50), nullable=False)  # "sale" или "consignment"
    product_id = db.Column(db.Integer, nullable=False)  # ID товара
    amount = db.Column(db.Float, nullable=False)  # Сумма операции
    date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False, default='pending')  # pending, confirmed, cancelled

    def __repr__(self):
        return f'<UserOperation {self.id} - {self.operation_type} - Amount: {self.amount}>'

# Функция для удаления всех данных из таблицы user_operations
def delete_all_operations():
    with app.app_context():
        try:
            # Удаляем все записи из таблицы user_operations
            num_deleted = db.session.query(UserOperation).delete()
            db.session.commit()
            print(f"Удалено {num_deleted} записей из таблицы user_operations.")
        except Exception as e:
            db.session.rollback()  # Откат изменений в случае ошибки
            print(f"Ошибка при удалении данных: {e}")

if __name__ == "__main__":
    delete_all_operations()
