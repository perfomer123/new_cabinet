import sqlite3
import pandas as pd
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
from functools import wraps
from email_sender import send_email
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
import json
import os
import threading
import time
import numpy as np
import yookassa
import logging
from yookassa.domain.exceptions import UnauthorizedError
from sqlalchemy import create_engine
import pytz
from update_service import is_update_required

SECRET_KEY = "6f68bd57715ae163e42efec24e698d0f"

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Настройки YooKassa
yookassa.Configuration.account_id = '396396'
yookassa.Configuration.secret_key = 'live_s8H0Ts0UqGDXUKjwszCZBA-Jy049jFqWGjKQ8P0_gno'

# Установите путь ко второй базе данных
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SECONDARY_DATABASE_PATH = os.path.join(BASE_DIR, '/root/miner-data/file.db')

app = Flask(__name__)

app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'instance/users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    reset_token = db.Column(db.String(150), nullable=True)
    tariff_id = db.Column(db.Integer, db.ForeignKey('tariff.id'), nullable=True)
    tariff = db.relationship('Tariff', backref=db.backref('users', lazy=True))
    
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(250), nullable=True)
    notes = db.Column(db.Text, nullable=True)

class UserKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(50), nullable=True)  # Изменено на nullable=True
    start_date = db.Column(db.String(50), nullable=True)
    end_date = db.Column(db.String(50), nullable=True)
    tariff_id = db.Column(db.Integer, nullable=True)


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

class PartnerManagerAssociation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    partner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class ManagerSupervisorAssociation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Earning(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key_id = db.Column(db.Integer, db.ForeignKey('user_key.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(250), nullable=True)

    user = db.relationship('User', backref=db.backref('earnings', lazy=True))

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    tariff_id = db.Column(db.Integer, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    extension_days = db.Column(db.Integer, nullable=False)
    payment_date = db.Column(db.DateTime, default=datetime.utcnow)
    key = db.Column(db.String(150), nullable=False)
    payment_id = db.Column(db.String(150), nullable=False)
    processed = db.Column(db.Boolean, nullable=False, default=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Декоратор для проверки роли пользователя
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                flash('У вас нет доступа к этой странице.')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Инициализация базы данных
with app.app_context():
    db.create_all()

def add_user_if_not_exists(username, email, password, role):
    if not User.query.filter_by(email=email).first():
        user = User(username=username, email=email, password=generate_password_hash(password, method='sha256'), role=role)
        db.session.add(user)
        db.session.commit()

with app.app_context():
    add_user_if_not_exists('admin', 'admin@example.com', 'admin', 'admin')
    add_user_if_not_exists('partner', 'partner@example.com', 'partner', 'partner')
    add_user_if_not_exists('manager', 'manager@example.com', 'manager', 'manager')

def calculate_daily_rate(duration):
    if duration <= 30:
        daily_rate = 700 / 30
    elif duration <= 90:
        daily_rate = 1950 / 90
    elif duration <= 180:
        daily_rate = 3600 / 180
    elif duration <= 365:
        daily_rate = 6000 / 365
    else:
        daily_rate = 6000 / 365
    return daily_rate

def handle_status_change(user_key, old_status):
    try:
        partner = User.query.filter_by(id=user_key.user_id).first()
        if not partner:
            return

        # Поиск менеджера (может отсутствовать)
        manager_association = PartnerManagerAssociation.query.filter_by(partner_id=partner.id).first()
        manager = None
        if manager_association:
            manager = User.query.filter_by(id=manager_association.manager_id).first()

        # Поиск супервизора (может отсутствовать)
        supervisor = None
        if manager:
            supervisor_association = ManagerSupervisorAssociation.query.filter_by(manager_id=manager.id).first()
            if supervisor_association:
                supervisor = User.query.filter_by(id=supervisor_association.supervisor_id).first()

        # Получение тарифа партнёра
        partner_tariff = Tariff.query.filter_by(id=partner.tariff_id).first()
        if not partner_tariff:
            return

        # Получение тарифа менеджера (если менеджер существует)
        manager_tariff = None
        if manager:
            manager_tariff = Tariff.query.filter_by(id=manager.tariff_id).first()

        # Получение тарифа супервизора (если супервизор существует)
        supervisor_tariff = None
        if supervisor:
            supervisor_tariff = Tariff.query.filter_by(id=supervisor.tariff_id).first()

        # Логика начисления при смене статуса
        if old_status == 'new' and user_key.status == 'active':
            # Начисление партнёру
            partner_initial_earning = partner_tariff.partner_initial_payment
            db.session.add(Earning(
                user_id=partner.id,
                key_id=user_key.id,
                amount=round(partner_initial_earning, 1),
                description=f"Первоначальный заработок партнёра за активацию ключа {user_key.key}"
            ))

            # Начисление менеджеру, если он есть
            if manager and manager_tariff:
                manager_initial_earning = manager_tariff.manager_initial_payment
                db.session.add(Earning(
                    user_id=manager.id,
                    key_id=user_key.id,
                    amount=round(manager_initial_earning, 1),
                    description=f"Первоначальный заработок менеджера за активацию ключа {user_key.key}"
                ))

            # Начисление супервизору, если он есть
            if supervisor and supervisor_tariff:
                supervisor_initial_earning = supervisor_tariff.supervisor_initial_payment
                db.session.add(Earning(
                    user_id=supervisor.id,
                    key_id=user_key.id,
                    amount=round(supervisor_initial_earning, 1),
                    description=f"Первоначальный заработок супервизора за активацию ключа {user_key.key}"
                ))

            db.session.commit()
    except Exception as e:
        pass


def calculate_earnings(user_key, previous_end_date):
    try:
        partner = User.query.filter_by(id=user_key.user_id).first()
        if not partner:
            return

        partner_tariff = Tariff.query.filter_by(id=partner.tariff_id).first()
        if not partner_tariff:
            return

        if isinstance(previous_end_date, str):
            previous_end_date = datetime.strptime(previous_end_date, '%Y-%m-%d %H:%M:%S')

        start_date = datetime.strptime(user_key.start_date, '%Y-%m-%d %H:%M:%S')
        end_date = datetime.strptime(user_key.end_date, '%Y-%m-%d %H:%M:%S')

        current_date = datetime.now()
        effective_start_date = max(previous_end_date, current_date)
        extension_duration = (end_date - effective_start_date).days

        if extension_duration <= 0:
            return

        daily_rate = calculate_daily_rate(extension_duration)
        subscription_price = daily_rate * extension_duration
        partner_earning = subscription_price * (partner_tariff.partner_subscription_percentage / 100)

        # Начисление для партнёра
        db.session.add(Earning(
            user_id=partner.id,
            key_id=user_key.id,
            amount=round(partner_earning, 1),
            description=f"Заработок партнёра за продление ключа {user_key.key} на {extension_duration} дней, с {effective_start_date.strftime('%Y-%m-%d')} по {end_date.strftime('%Y-%m-%d')}, по тарифу {partner_tariff.name}"
        ))

        # Поиск менеджера (может отсутствовать)
        manager_association = PartnerManagerAssociation.query.filter_by(partner_id=partner.id).first()
        manager = None
        if manager_association:
            manager = User.query.filter_by(id=manager_association.manager_id).first()
            if manager:
                manager_tariff = Tariff.query.filter_by(id=manager.tariff_id).first()
                if manager_tariff:
                    manager_earning = subscription_price * (manager_tariff.manager_subscription_percentage / 100)
                    db.session.add(Earning(
                        user_id=manager.id,
                        key_id=user_key.id,
                        amount=round(manager_earning, 1),
                        description=f"Заработок менеджера за продление ключа {user_key.key} на {extension_duration} дней, с {effective_start_date.strftime('%Y-%м-%d')} по {end_date.strftime('%Y-%m-%d')}, по тарифу {manager_tariff.name}"
                    ))

        # Поиск супервизора (может отсутствовать)
        supervisor = None
        if manager:
            supervisor_association = ManagerSupervisorAssociation.query.filter_by(manager_id=manager.id).first()
            if supervisor_association:
                supervisor = User.query.filter_by(id=supervisor_association.supervisor_id).first()
                if supervisor:
                    supervisor_tariff = Tariff.query.filter_by(id=supervisor_tariff.id).first()
                    if supervisor_tariff:
                        supervisor_earning = subscription_price * (supervisor_tariff.supervisor_subscription_percentage / 100)
                        db.session.add(Earning(
                            user_id=supervisor.id,
                            key_id=user_key.id,
                            amount=round(supervisor_earning, 1),
                            description=f"Заработок супервизора за продление ключа {user_key.key} на {extension_duration} дней, с {effective_start_date.strftime('%Y-%m-%d')} по {end_date.strftime('%Y-%м-%d')}, по тарифу {supervisor_tariff.name}"
                        ))

        db.session.commit()
    except Exception as e:
        pass


        

def sync_keys():
    with app.app_context():
        conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
        cursor = conn.cursor()

        user_keys = UserKey.query.all()

        for user_key in user_keys:
            cursor.execute("SELECT status, start_date, end_date, tariff_id FROM user_keys WHERE key=?", (user_key.key,))
            result = cursor.fetchone()
            if result:
                previous_end_date = datetime.strptime(user_key.end_date, '%Y-%m-%d %H:%M:%S') if user_key.end_date else None
                old_status = user_key.status
                user_key.status = result[0]
                user_key.start_date = result[1]
                user_key.end_date = result[2]
                user_key.tariff_id = result[3]
                db.session.commit()

                handle_status_change(user_key, old_status)

                if user_key.end_date:
                    new_end_date = datetime.strptime(user_key.end_date, '%Y-%m-%d %H:%M:%S')
                    if previous_end_date and new_end_date > previous_end_date and new_end_date > datetime.now():
                        extension_duration = (new_end_date - previous_end_date).days
                        calculate_earnings(user_key, previous_end_date)

        conn.close()

def sync_keys_from_external_db(user_id):
    with app.app_context():
        conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
        cursor = conn.cursor()

        user_keys = UserKey.query.filter_by(user_id=user_id).all()

        for user_key in user_keys:
            cursor.execute("SELECT status, start_date, end_date, tariff_id FROM user_keys WHERE key=?", (user_key.key,))
            result = cursor.fetchone()
            if result:
                previous_end_date = datetime.strptime(user_key.end_date, '%Y-%m-%d %H:%M:%S') if user_key.end_date else None
                old_status = user_key.status
                user_key.status = result[0]
                user_key.start_date = result[1]
                user_key.end_date = result[2]
                user_key.tariff_id = result[3]
                db.session.commit()

                handle_status_change(user_key, old_status)

                if user_key.end_date:
                    new_end_date = datetime.strptime(user_key.end_date, '%Y-%m-%d %H:%M:%S')
                    if previous_end_date and new_end_date > previous_end_date and new_end_date > datetime.now():
                        extension_duration = (new_end_date - previous_end_date).days
                        calculate_earnings(user_key, previous_end_date)

        conn.close()



def extend_key_subscription(user_id, tariff_id, amount, extension_days, key):
    conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
    cursor = conn.cursor()
    
    # Найдите ключ по его значению
    cursor.execute("SELECT * FROM user_keys WHERE key=?", (key,))
    user_key = cursor.fetchone()
    
    if not user_key:
        return {'status': False, 'message': 'Key not found'}, 404

    # Вычисление новой даты окончания подписки
    new_end_date = calculate_new_end_date(user_key[6], extension_days)

    # Обновление статуса и имени ключа
    current_status = user_key[7]
    new_status = 'active'  # Всегда активируем ключ после успешного платежа
    new_key_name = user_key[3].replace("(OFF) ", "") if user_key[3] and user_key[3].startswith("(OFF)") else user_key[3]

    # Обновление записи о ключе
    cursor.execute(
        "UPDATE user_keys SET end_date=?, status=?, key_name=? WHERE key=?", 
        (new_end_date.strftime('%Y-%m-%d %H:%M:%S'), new_status, new_key_name, key)
    )
    conn.commit()

    cursor.execute("SELECT status, key_name FROM user_keys WHERE key=?", (key,))
    updated_status, updated_key_name = cursor.fetchone()

    conn.close()
    return {'status': True, 'new_subscription_end_date': new_end_date.strftime('%Y-%m-%d %H:%M:%S')}, 200


@app.route('/api/payment', methods=['POST'])
def process_payment():
    try:
        # Получаем данные из запроса
        data = request.get_json()
        
        app.logger.info(f"Получены данные: {data}")  # Логируем полученные данные

        # Проверка наличия и корректности secret_key
        secret_key = data.get('secret_key')
        if secret_key != SECRET_KEY:
            return jsonify({'status': False, 'message': 'Unauthorized'}), 401

        # Извлечение данных из JSON
        user_id = data.get('user_id')
        tariff_id = data.get('tariff_id')
        amount = data.get('amount')
        extension_days = data.get('extension_days')
        key = data.get('key')
        payment_date = data.get('payment_date')

        # Проверка обязательных полей на наличие значений
        if not all([user_id, tariff_id, amount, extension_days, key]):
            return jsonify({'status': False, 'message': 'Missing required fields'}), 400

        # Преобразование данных и проверка на None перед преобразованием
        user_id = int(user_id) if user_id else None
        tariff_id = int(tariff_id) if tariff_id else None
        amount = float(amount) if amount else None
        extension_days = int(extension_days) if extension_days else None
        payment_date = datetime.strptime(payment_date, "%Y-%m-%d %H:%M:%S") if payment_date else None

        # Убедись, что после проверки поля не None
        if not all([user_id, tariff_id, amount, extension_days, payment_date]):
            return jsonify({'status': False, 'message': 'Invalid data fields'}), 400

        # Вызов общей функции для продления подписки
        result, status_code = extend_key_subscription(user_id, tariff_id, amount, extension_days, key)
        
        # Если всё прошло успешно, добавляем информацию о платеже в базу
        if status_code == 200:
            new_payment = Payment(
                user_id=user_id,
                tariff_id=tariff_id,
                amount=amount,
                extension_days=extension_days,
                payment_id=data.get('payment_id'),
                payment_date=payment_date,
                key=key,
                processed=True
            )
            db.session.add(new_payment)
            db.session.commit()

        return jsonify(result), status_code

    except Exception as e:
        app.logger.error(f"Error processing payment: {e}")
        return jsonify({'status': False, 'message': str(e)}), 500




# Маршрут для главной страницы
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Вход</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .login-container {
                max-width: 400px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .login-container h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .form-group {
                margin-bottom: 15px;
            }
            .btn-primary {
                display: block;
                width: 100%;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>Вход</h1>
            <form method="POST" action="/login">
                <div class="form-group">
                    <input type="email" name="email" class="form-control" placeholder="Email" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" class="form-control" placeholder="Пароль" required>
                </div>
                <button type="submit" class="btn btn-primary">Войти</button>
                <a href="{{ url_for('reset_password') }}">Забыли пароль?</a>
            </form>
        </div>
    </body>
    </html>
    ''')

# Маршруты для входа и выхода из системы
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))

        flash('Неверный email или пароль')
        return redirect(url_for('login'))

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Вход</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .login-container {
                max-width: 400px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .login-container h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .form-group {
                margin-bottom: 15px;
            }
            .btn-primary {
                display: block;
                width: 100%;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>Вход</h1>
            <form method="POST">
                <div class="form-group">
                    <input type="email" name="email" class="form-control" placeholder="Email">
                </div>
                <div class="form-group">
                    <input type="password" name="password" class="form-control" placeholder="Пароль">
                </div>
                <button type="submit" class="btn btn-primary">Войти</button>
                <a href="{{ url_for('reset_password') }}">Забыли пароль?</a>
            </form>
        </div>
    </body>
    </html>
    ''')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    dashboard_html = '''
    <h1>Панель управления</h1>
    <a href="/logout">Выйти</a>
    <a href="https://cabinet.sovamonitoring.com/daily_metrics">Ежедневные метрики</a>
    '''
    if current_user.role == 'admin':
        dashboard_html += '<a href="/admin">Панель администратора</a>'
        dashboard_html += '<a href="/manage_statuses">Управление</a>'  # Добавляем ссылку "Управление" только для администратора
    elif current_user.role == 'partner':
        dashboard_html += '<a href="/partner">Панель партнера</a>'
    elif current_user.role == 'manager':
        dashboard_html += '<a href="/manager">Панель менеджера</a>'
    elif current_user.role == 'supervisor':
        dashboard_html += '<a href="/supervisor">Панель супервизора</a>'
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Панель управления</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .dashboard {
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .dashboard h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .dashboard a {
                display: block;
                margin: 10px 0;
                padding: 10px;
                background-color: #007bff;
                color: white;
                text-align: center;
                border-radius: 4px;
                text-decoration: none;
            }
            .dashboard a:hover {
                background-color: #0056b3;
            }
            .btn-logout {
                display: block;
                margin: 20px auto;
                width: 100px;
            }
        </style>
    </head>
    <body>
        <div class="dashboard">
            ''' + dashboard_html + '''
        </div>
    </body>
    </html>
    ''')




@app.route('/manage_statuses', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_statuses():
    if request.method == 'POST':
        new_status = int(request.form['notify_monitoring'])
        update_notify_monitoring_status_for_all_users(new_status)
        flash('Статус уведомлений обновлен для всех пользователей')
        session['notify_monitoring'] = new_status  # Сохраняем новое значение в сессии
        return redirect(url_for('manage_statuses'))

    current_status = session.get('notify_monitoring', 1)  # Получаем значение из сессии или устанавливаем по умолчанию 1

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Управление статусами</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .form-container {
                max-width: 500px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .form-container h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .form-group {
                margin-bottom: 15px;
            }
            .btn-primary {
                display: block;
                width: 100%;
            }
            .alert {
                margin-top: 20px;
            }
            .btn-back {
                display: block;
                margin-top: 20px;
                width: 100%;
            }
        </style>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                var statusMessage = "{{ get_flashed_messages() }}"
                if (statusMessage) {
                    var alertBox = document.getElementById('statusAlert');
                    alertBox.style.display = 'block';
                }
            });
        </script>
    </head>
    <body>
        <div class="form-container">
            <h1>Управление статусами</h1>
            {% with messages = get_flashed_messages() %}
                {% if messages %}
                    <div class="alert alert-success">{{ messages[0] }}</div>
                {% endif %}
            {% endwith %}
            <form method="POST">
                <div class="form-group">
                    <label for="notify_monitoring">Статус уведомлений:</label>
                    <select id="notify_monitoring" name="notify_monitoring" class="form-control">
                        <option value="1" {% if current_status == 1 %}selected{% endif %}>Активно</option>
                        <option value="0" {% if current_status == 0 %}selected{% endif %}>Неактивно</option>
                    </select>
                </div>
                <button type="submit" class="btn btn-primary">Обновить статус</button>
            </form>
            <a href="/data" class="btn btn-secondary btn-back">Просмотр данных</a>
            <a href="/keys_management" class="btn btn-secondary btn-back">Управление ключами</a>
            <a href="{{ url_for('dashboard') }}" class="btn btn-secondary btn-back">Назад</a>
        </div>
    </body>
    </html>
    ''', current_status=current_status)






def update_notify_monitoring_status_for_all_users(new_status):
    try:
        conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET notify_monitoring = ?", (new_status,))
        conn.commit()
        conn.close()

        print(f'Successfully updated notify_monitoring status to {new_status} for all users.')
    except Exception as e:
        print(f'Failed to update notify_monitoring status: {e}')




def get_user_keys(page=1, per_page=10, start_date=None):
    query = UserKey.query

    if start_date and start_date != 'None':
        try:
            start_date_dt = datetime.strptime(start_date, '%Y-%m-%d').date()
            query = query.filter(func.date(UserKey.start_date) == start_date_dt)
        except ValueError:
            print("Invalid date format")
    else:
        start_date = None  # Ensure that start_date is None if it's not valid or 'None'

    query = query.order_by(UserKey.start_date.asc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    user_keys = pagination.items
    total = pagination.total

    conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
    cursor = conn.cursor()
    user_keys_info = {}

    for key in user_keys:
        cursor.execute("SELECT status, start_date, end_date, tariff_id FROM user_keys WHERE key=?", (key.key,))
        result = cursor.fetchone()
        if result:
            user_keys_info[key.key] = {
                'status': result[0] if result[0] else 'None',
                'start_date': result[1] if result[1] else 'None',
                'end_date': result[2] if result[2] else 'None',
                'tariff_id': result[3]
            }
        else:
            user_keys_info[key.key] = {
                'status': 'None',
                'start_date': 'None',
                'end_date': 'None',
                'tariff_id': 'None'
            }

    available_tariffs = pd.read_sql_query("SELECT id, name FROM tariffs", conn)
    available_tariffs_dict = available_tariffs.set_index('id').to_dict()['name']
    conn.close()

    processed_user_keys = []
    for key in user_keys:
        key_info = user_keys_info.get(key.key, {})
        user = User.query.filter_by(id=key.user_id).first()
        if user is not None:
            username = user.username
        else:
            username = 'Unknown'  # Или любое другое значение по умолчанию

        key_data = {
            'key': key.key,
            'status': key_info.get('status', 'None'),
            'start_date': key_info.get('start_date', 'None'),
            'end_date': key_info.get('end_date', 'None'),
            'tariff_name': available_tariffs_dict.get(key_info.get('tariff_id'), 'N/A'),
            'username': username
        }
        processed_user_keys.append(key_data)

    return processed_user_keys, total


    

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    start_date = request.args.get('start_date') if request.method == 'GET' else request.form.get('start_date')

    keys, total = get_user_keys(page, per_page, start_date)

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Панель администратора</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .admin-panel {
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .admin-panel h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .category {
                margin-bottom: 20px;
            }
            .category h3 {
                margin-bottom: 10px;
            }
            .category a {
                display: block;
                margin: 5px 0;
                padding: 10px;
                background-color: #007bff;
                color: white;
                text-align: center;
                border-radius: 4px;
                text-decoration: none;
            }
            .category a:hover {
                background-color: #0056b3;
            }
            .btn-back {
                display: block;
                margin: 20px auto;
                width: 100px;
                background-color: #6c757d;
                color: white;
                text-align: center;
                border-radius: 4px;
                text-decoration: none;
                padding: 10px 20px;
            }
            .keys-container {
                margin-top: 20px;
            }
            .date-form {
                text-align: center;
                margin-bottom: 20px;
            }
            .pagination {
                display: flex;
                justify-content: center;
                margin-top: 20px;
            }
            .pagination a {
                margin: 0 5px;
                padding: 8px 16px;
                background-color: #007bff;
                color: white;
                text-decoration: none;
                border-radius: 4px;
            }
            .pagination a:hover {
                background-color: #0056b3;
            }
            .pagination .active {
                background-color: #0056b3;
                pointer-events: none;
            }
        </style>
        <link rel="stylesheet" href="https://code.jquery.com/ui/1.12.1/themes/base/jquery-ui.css">
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <script src="https://code.jquery.com/ui/1.12.1/jquery-ui.js"></script>
        <script>
            $(function() {
                $("#start_date").datepicker({
                    dateFormat: 'yy-mm-dd',
                    onSelect: function(dateText) {
                        $("#dateForm").submit();
                    }
                });
            });

            function filterTable() {
                var input, filter, table, tr, td, i, j, txtValue;
                input = document.getElementById("tableFilter");
                filter = input.value.toUpperCase();
                table = document.getElementById("keysTable");
                tr = table.getElementsByTagName("tr");

                for (i = 1; i < tr.length; i++) {
                    tr[i].style.display = "none";
                    td = tr[i].getElementsByTagName("td");
                    for (j = 0; j < td.length; j++) {
                        if (td[j]) {
                            txtValue = td[j].textContent || td[j].innerText;
                            if (txtValue.toUpperCase().indexOf(filter) > -1) {
                                tr[i].style.display = "";
                                break;
                            }
                        }
                    }
                }
            }
        </script>
    </head>
    <body>
        <div class="admin-panel">
            <h1>Панель администратора</h1>
            <div class="category">
                <h3>Пользователи</h3>
                <a href="/create_user">Создать пользователя</a>
                <a href="/users">Просмотр пользователей</a>
            </div>
            <div class="category">
                <h3>Тарифы</h3>
                <a href="/create_tariff">Создать тариф</a>
                <a href="/tariffs">Просмотр тарифов</a>
            </div>
            <a href="/assign_partner_manager">Назначить партнера менеджеру</a>
            <a href="{{ url_for('dashboard') }}" class="btn-back">Назад</a>
            <div class="keys-container">
                <h3>Активированные ключи</h3>
                <form method="POST" id="dateForm" class="date-form">
                    <label for="start_date">Дата начала:</label>
                    <input type="text" id="start_date" name="start_date" value="{{ start_date }}">
                    <button type="submit" class="btn btn-primary">Показать</button>
                </form>
                <input type="text" id="tableFilter" onkeyup="filterTable()" placeholder="Фильтровать по ключевым словам..." class="form-control mb-3">
                <div class="form-group">
                    <label for="per_page">Записей на странице:</label>
                    <select id="per_page" name="per_page" class="form-control" onchange="window.location.href='?per_page='+this.value+'&start_date={{ start_date }}'">
                        <option value="10" {% if per_page == 10 %}selected{% endif %}>10</option>
                        <option value="20" {% if per_page == 20 %}selected{% endif %}>20</option>
                        <option value="30" {% if per_page == 30 %}selected{% endif %}>30</option>
                    </select>
                </div>
                <table class="table table-striped" id="keysTable">
                    <thead class="thead-dark">
                        <tr>
                            <th>Партнер</th>
                            <th>Ключ</th>
                            <th>Дата начала</th>
                            <th>Дата окончания</th>
                            <th>Статус</th>
                            <th>Тариф</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for key in keys %}
                        <tr>
                            <td>{{ key.username }}</td>
                            <td>{{ key.key }}</td>
                            <td>{{ key.start_date }}</td>
                            <td>{{ key.end_date }}</td>
                            <td>{{ key.status }}</td>
                            <td>{{ key.tariff_name }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                <div class="pagination">
                    {% if page > 1 %}
                    <a href="?page={{ page - 1 }}&per_page={{ per_page }}&start_date={{ start_date }}">&laquo; Предыдущая</a>
                    {% endif %}
                    {% for p in range(1, (total // per_page) + 2) %}
                    <a href="?page={{ p }}&per_page={{ per_page }}&start_date={{ start_date }}" class="{% if p == page %}active{% endif %}">{{ p }}</a>
                    {% endfor %}
                    {% if page * per_page < total %}
                    <a href="?page={{ page + 1 }}&per_page={{ per_page }}&start_date={{ start_date }}">Следующая &raquo;</a>
                    {% endif %}
                </div>
            </div>
        </div>
    </body>
    </html>
    ''', keys=keys, start_date=start_date, page=page, per_page=per_page, total=total)




@app.route('/create_user', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_user():
    tariffs = Tariff.query.all()
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        notes = request.form['notes']
        role = request.form['role']
        tariff_id = request.form['tariff_id']

        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже существует')
            return redirect(url_for('create_user'))

        if User.query.filter_by(email=email).first():
            flash('Email уже существует')
            return redirect(url_for('create_user'))

        new_user = User(
            username=username, 
            email=email,
            phone=phone,
            address=address,
            notes=notes,
            password=generate_password_hash(secrets.token_urlsafe(16), method='sha256'), 
            role=role,
            tariff_id=tariff_id
        )
        db.session.add(new_user)
        db.session.commit()

        token = secrets.token_urlsafe(16)
        reset_link = url_for('reset_password_token', token=token, _external=True)
        
        if email:
            subject = 'Приглашение к регистрации'
            message = f'Вы приглашены зарегистрироваться. Перейдите по ссылке для установки пароля: {reset_link}'
            send_email(email, subject, message)

        flash('Пользователь успешно создан')
        return redirect(url_for('admin_dashboard'))

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Создать пользователя</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .form-container {
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .form-container h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .form-group {
                margin-bottom: 15px;
            }
            .btn-primary {
                display: block;
                width: 100%;
            }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h1>Создать пользователя</h1>
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="username" class="form-control" placeholder="Имя пользователя" required>
                </div>
                <div class="form-group">
                    <input type="email" name="email" class="form-control" placeholder="Email" required>
                </div>
                <div class="form-group">
                    <input type="text" name="phone" class="form-control" placeholder="Телефон">
                </div>
                <div class="form-group">
                    <input type="text" name="address" class="form-control" placeholder="Адрес">
                </div>
                <div class="form-group">
                    <textarea name="notes" class="form-control" placeholder="Примечание"></textarea>
                </div>
                <div class="form-group">
                    <select name="role" class="form-control">
                        <option value="partner">Партнер</option>
                        <option value="manager">Менеджер</option>
                        <option value="supervisor">Супервизор</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="tariff_id">Тариф</label>
                    <select id="tariff_id" name="tariff_id" class="form-control" required>
                        {% for tariff in tariffs %}
                        <option value="{{ tariff.id }}">{{ tariff.name }}</option>
                        {% endfor %}
                    </select>
                </div>
                <button type="submit" class="btn btn-primary">Создать пользователя</button>
            </form>
            {% with messages = get_flashed_messages() %}
                {% if messages %}
                    <div class="alert alert-warning" role="alert">
                        {{ messages[0] }}
                    </div>
                {% endif %}
            {% endwith %}
        </div>
    </body>
    </html>
    ''', tariffs=tariffs)




@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_user':
            user.username = request.form['username']
            user.email = request.form['email']
            user.phone = request.form['phone']
            user.address = request.form['address']
            user.notes = request.form['notes']
            if request.form['password']:
                user.password = generate_password_hash(request.form['password'], method='sha256')
            user.role = request.form['role']

            selected_tariff = user.tariff  # Assume the tariff was already assigned when the user was created

            # Проверка при назначении партнера с ограниченным тарифом
            if user.role == 'partner' and selected_tariff and selected_tariff.restricted:
                if request.form.get('manager_id'):
                    flash('Партнера с этим тарифом нельзя назначать менеджеру или супервизору', 'danger')
                    return redirect(url_for('edit_user', user_id=user_id))

            # Назначение супервизоров для менеджеров
            if user.role == 'manager':
                supervisor_id = request.form.get('supervisor_id')
                existing_association = ManagerSupervisorAssociation.query.filter_by(manager_id=user_id).first()
                if existing_association:
                    if supervisor_id:
                        existing_association.supervisor_id = supervisor_id
                    else:
                        db.session.delete(existing_association)
                elif supervisor_id:
                    new_association = ManagerSupervisorAssociation(manager_id=user_id, supervisor_id=supervisor_id)
                    db.session.add(new_association)

            # Назначение менеджеров для партнеров
            if user.role == 'partner':
                manager_id = request.form.get('manager_id')
                existing_association = PartnerManagerAssociation.query.filter_by(partner_id=user_id).first()
                if existing_association:
                    if manager_id:
                        existing_association.manager_id = manager_id
                    else:
                        db.session.delete(existing_association)
                elif manager_id:
                    new_association = PartnerManagerAssociation(partner_id=user_id, manager_id=manager_id)
                    db.session.add(new_association)
            db.session.commit()
            flash('Пользователь успешно обновлен', 'success')
        
        elif action == 'add_keys':
            new_keys = request.form.getlist('new_keys')
            if new_keys:
                conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
                cursor = conn.cursor()
                for key in new_keys:
                    cursor.execute("SELECT status, start_date, end_date, tariff_id FROM user_keys WHERE key=?", (key,))
                    result = cursor.fetchone()
                    if result:
                        user_key = UserKey(
                            user_id=user_id,
                            key=key,
                            status=result[0],  # Оставляем статус, как есть
                            start_date=result[1],
                            end_date=result[2],
                            tariff_id=result[3]
                        )
                        db.session.add(user_key)
                conn.close()
                db.session.commit()
                flash('Ключи успешно добавлены', 'success')
        
        elif action == 'detach_keys':
            detach_keys = request.form.getlist('detach_keys')
            if detach_keys:
                for key in detach_keys:
                    UserKey.query.filter_by(user_id=user_id, key=key).delete()
                db.session.commit()
                flash('Ключи успешно отвязаны', 'success')
        
        elif action == 'add_manual_key':
            manual_key = request.form.get('manual_key')
            if manual_key:
                existing_key = UserKey.query.filter_by(key=manual_key).first()
                if existing_key:
                    flash('Этот ключ уже назначен другому пользователю', 'danger')
                else:
                    conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
                    cursor = conn.cursor()
                    cursor.execute("SELECT status, start_date, end_date, tariff_id FROM user_keys WHERE key=?", (manual_key,))
                    result = cursor.fetchone()
                    if result:
                        user_key = UserKey(
                            user_id=user_id,
                            key=manual_key,
                            status=result[0],  # Оставляем статус, как есть
                            start_date=result[1],
                            end_date=result[2],
                            tariff_id=result[3]
                        )
                        db.session.add(user_key)
                    conn.close()
                    db.session.commit()
                    flash('Ключ успешно добавлен', 'success')
        
        return redirect(url_for('edit_user', user_id=user_id))

    # Получение данных о ключах пользователя из локальной базы данных
    user_keys = UserKey.query.filter_by(user_id=user_id).all()
    tariffs = Tariff.query.all()

    # Получение данных о ключах пользователя из внешней базы данных
    conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
    cursor = conn.cursor()
    user_keys_info = {}
    for key in user_keys:
        cursor.execute("SELECT status, start_date, end_date, tariff_id FROM user_keys WHERE key=?", (key.key,))
        result = cursor.fetchone()
        if result:
            user_keys_info[key.key] = {
                'status': result[0],
                'start_date': result[1],
                'end_date': result[2],
                'tariff_id': result[3]
            }
        else:
            user_keys_info[key.key] = {
                'status': None,
                'start_date': '',
                'end_date': '',
                'tariff_id': ''
            }
    available_keys = pd.read_sql_query("SELECT key, status, start_date, end_date, tariff_id FROM user_keys", conn)
    available_tariffs = pd.read_sql_query("SELECT id, name FROM tariffs", conn)
    conn.close()

    available_keys = available_keys.to_dict(orient='records')
    available_tariffs_dict = available_tariffs.set_index('id').to_dict()['name']

    # Исключение уже добавленных ключей из списка доступных ключей
    all_assigned_keys = {key.key for key in UserKey.query.with_entities(UserKey.key).all()}
    available_keys = [key for key in available_keys if key['key'] not in all_assigned_keys]

    # Получение всех супервизоров и менеджеров для отображения в форме
    supervisors = User.query.filter_by(role='supervisor').all()
    managers = User.query.filter_by(role='manager').all()

    # Получение текущих ассоциаций пользователя
    current_supervisor_id = None
    current_manager_id = None
    if user.role == 'manager':
        association = ManagerSupervisorAssociation.query.filter_by(manager_id=user_id).first()
        if association:
            current_supervisor_id = association.supervisor_id
    elif user.role == 'partner':
        association = PartnerManagerAssociation.query.filter_by(partner_id=user_id).first()
        if association:
            current_manager_id = association.manager_id

    # Обработка данных перед отправкой в шаблон
    processed_user_keys = []
    for key in user_keys:
        key_info = user_keys_info.get(key.key, {})
        key_data = {
            'key': key.key,
            'status': key_info.get('status', None),
            'start_date': key_info.get('start_date', ''),
            'end_date': key_info.get('end_date', ''),
            'tariff_name': available_tariffs_dict.get(key_info.get('tariff_id'), 'N/A')
        }
        processed_user_keys.append(key_data)

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Редактировать пользователя</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .form-container {
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .form-container h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .form-group {
                margin-bottom: 15px;
            }
            .btn-primary {
                display: block;
                width: 100%;
            }
            .keys-container {
                margin-top: 20px;
            }
            .btn-back {
                display: inline-block;
                margin-bottom: 20px;
                padding: 10px 20px;
                background-color: #6c757d;
                color: white;
                text-align: center;
                border-radius: 4px;
                text-decoration: none;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }
            table, th, td {
                border: 1px solid #ddd;
            }
            th, td {
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
            tr:hover {
                background-color: #f5f5f5;
            }
            .details-row {
                display: none;
            }
            .modal {
                display: none;
                position: fixed;
                z-index: 1;
                left: 0;
                top: 0;
                width: 100%;
                height: 100%;
                overflow: auto;
                background-color: rgba(0, 0, 0, 0.4);
                justify-content: center;
                align-items: center;
            }
            .modal-content {
                background-color: #fefefe;
                margin: auto;
                padding: 20px;
                border: 1px solid #888;
                width: 80%;
                max-width: 800px;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }
            .close {
                color: #aaa;
                float: right;
                font-size: 28px;
                font-weight: bold;
            }
            .close:hover,
            .close:focus {
                color: black;
                text-decoration: none;
                cursor: pointer;
            }
        </style>
        <script>
            function toggleDetails(rowId) {
                var row = document.getElementById(rowId);
                if (row.style.display === "none") {
                    row.style.display = "table-row";
                } else {
                    row.style.display = "none";
                }
            }

            function openModal(modalId) {
                var modal = document.getElementById(modalId);
                modal.style.display = "flex";
            }

            function closeModal(modalId) {
                var modal = document.getElementById(modalId);
                modal.style.display = "none";
            }

            window.onclick = function(event) {
                var modals = document.getElementsByClassName("modal");
                for (var i = 0; i < modals.length; i++) {
                    if (event.target == modals[i]) {
                        modals[i].style.display = "none";
                    }
                }
            }
        </script>
    </head>
    <body>
        <div class="form-container">
            <a href="{{ url_for('admin_dashboard') }}" class="btn-back">Назад</a>
            <h1>Редактировать пользователя</h1>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    <div class="alert-container">
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    </div>
                {% endif %}
            {% endwith %}
            <form method="POST">
                <input type="hidden" name="action" value="update_user">
                <div class="form-group">
                    <label for="username">Имя пользователя</label>
                    <input type="text" name="username" class="form-control" value="{{ user.username }}" required>
                </div>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" name="email" class="form-control" value="{{ user.email }}" required>
                </div>
                <div class="form-group">
                    <label for="phone">Телефон</label>
                    <input type="text" name="phone" class="form-control" value="{{ user.phone }}">
                </div>
                <div class="form-group">
                    <label for="address">Адрес</label>
                    <input type="text" name="address" class="form-control" value="{{ user.address }}">
                </div>
                <div class="form-group">
                    <label for="notes">Примечание</label>
                    <textarea name="notes" class="form-control">{{ user.notes }}</textarea>
                </div>
                <div class="form-group">
                    <label for="password">Пароль</label>
                    <input type="password" name="password" class="form-control">
                </div>
                <div class="form-group">
                    <label for="role">Роль</label>
                    <select name="role" class="form-control">
                        <option value="partner" {% if user.role == 'partner' %}selected{% endif %}>Партнер</option>
                        <option value="manager" {% if user.role == 'manager' %}selected{% endif %}>Менеджер</option>
                        <option value="supervisor" {% if user.role == 'supervisor' %}selected{% endif %}>Супервизор</option>
                    </select>
                </div>
                {% if user.role == 'manager' %}
                <div class="form-group">
                    <label for="supervisor_id">Назначить супервизора</label>
                    <select name="supervisor_id" class="form-control">
                        <option value="">Без супервизора</option>
                        {% for supervisor in supervisors %}
                        <option value="{{ supervisor.id }}" {% if current_supervisor_id == supervisor.id %}selected{% endif %}>{{ supervisor.username }}</option>
                        {% endfor %}
                    </select>
                </div>
                {% elif user.role == 'partner' %}
                <div class="form-group">
                    <label for="manager_id">Назначить менеджера</label>
                    <select name="manager_id" class="form-control">
                        <option value="">Без менеджера</option>
                        {% for manager in managers %}
                        <option value="{{ manager.id }}" {% if current_manager_id == manager.id %}selected{% endif %}>{{ manager.username }}</option>
                        {% endfor %}
                    </select>
                    {% if selected_tariff and selected_tariff.restricted %}
                    <small class="text-danger">Партнера с этим тарифом нельзя назначать менеджеру или супервизору.</small>
                    {% endif %}
                </div>
                {% endif %}
                <button type="submit" class="btn btn-primary">Сохранить изменения</button>
            </form>
            <div class="keys-container">
                <h2>Уже добавленные ключи</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Ключ</th>
                            <th>Статус</th>
                            <th>Дата начала</th>
                            <th>Дата окончания</th>
                            <th>Тариф</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for key in processed_user_keys %}
                        <tr onclick="toggleDetails('details-{{ loop.index }}')">
                            <td>{{ key.key }}</td>
                            <td>{{ key.status }}</td>
                            <td>{{ key.start_date }}</td>
                            <td>{{ key.end_date }}</td>
                            <td>{{ key.tariff_name }}</td>
                        </tr>
                        <tr id="details-{{ loop.index }}" class="details-row">
                            <td colspan="5">
                                <strong>Статус:</strong> {{ key.status }}<br>
                                <strong>Дата начала:</strong> {{ key.start_date }}<br>
                                <strong>Дата окончания:</strong> {{ key.end_date }}<br>
                                <strong>Тариф:</strong> {{ key.tariff_name }}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            <button class="btn btn-secondary" onclick="openModal('addKeysModal')">Добавить ключи</button>
            <button class="btn btn-secondary" onclick="openModal('detachKeysModal')">Отвязать ключи</button>
            <button class="btn btn-secondary" onclick="openModal('manualKeyModal')">Добавить ключ вручную</button>
        </div>

        <div id="addKeysModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('addKeysModal')">&times;</span>
                <h2>Добавить ключи</h2>
                <form method="POST">
                    <input type="hidden" name="action" value="add_keys">
                    <div class="form-group">
                        <label for="new_keys">Добавить существующие ключи</label>
                        <select name="new_keys" class="form-control" multiple>
                            {% for key in available_keys %}
                            <option value="{{ key['key'] }}">{{ key['key'] }} ({{ key['status'] }}, Начало: {{ key['start_date'] }}, Конец: {{ key['end_date'] }}, Тариф: {{ available_tariffs_dict.get(key['tariff_id'], 'N/A') }})</option>
                            {% endfor %}
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary">Добавить ключи</button>
                </form>
            </div>
        </div>

        <div id="detachKeysModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('detachKeysModal')">&times;</span>
                <h2>Отвязать ключи</h2>
                <form method="POST">
                    <input type="hidden" name="action" value="detach_keys">
                    <div class="form-group">
                        <label for="detach_keys">Отвязать ключи</label>
                        <select name="detach_keys" class="form-control" multiple>
                            {% for key in processed_user_keys %}
                            <option value="{{ key.key }}">{{ key.key }} ({{ key.status }}, Начало: {{ key.start_date }}, Конец: {{ key.end_date }}, Тариф: {{ key.tariff_name }})</option>
                            {% endfor %}
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary">Отвязать ключи</button>
                </form>
            </div>
        </div>

        <div id="manualKeyModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('manualKeyModal')">&times;</span>
                <h2>Добавить ключ вручную</h2>
                <form method="POST">
                    <input type="hidden" name="action" value="add_manual_key">
                    <div class="form-group">
                        <label for="manual_key">Ключ</label>
                        <input type="text" name="manual_key" class="form-control">
                    </div>
                    <button type="submit" class="btn btn-primary">Добавить ключ</button>
                </form>
            </div>
        </div>
    </body>
    </html>
    ''', user=user, available_keys=available_keys, processed_user_keys=processed_user_keys, available_tariffs_dict=available_tariffs_dict, supervisors=supervisors, managers=managers, current_supervisor_id=current_supervisor_id, current_manager_id=current_manager_id)


@app.route('/key_access/<key>', methods=['GET'])
@login_required
@role_required('admin')
def key_access(key):
    # Путь к базе данных /root/websocket/devices_data.db
    devices_db_path = '/root/websocket/devices_data.db'
    
    try:
        conn = sqlite3.connect(devices_db_path)
        cursor = conn.cursor()

        # Выполняем запрос для получения данных по uid ключа
        cursor.execute("SELECT * FROM device_data WHERE uid = ?", (key,))
        device_data = cursor.fetchone()
        
        if device_data:
            device_info = {
                'id': device_data[0],
                'uid': device_data[1],
                'ip': device_data[2],
                'port': device_data[3],
                'data': device_data[4],
                'timestamp': device_data[5]
            }

            # Попытка структурировать данные в поле 'data' как JSON
            try:
                structured_data = json.loads(device_info['data'])
            except (json.JSONDecodeError, TypeError):
                structured_data = None  # Если данные не в формате JSON

            # Вычисляем разницу во времени
            timestamp_format = "%Y-%m-%d %H:%M:%S"
            # Преобразуем время из базы данных к UTC
            utc = pytz.utc
            timestamp = datetime.strptime(device_info['timestamp'], timestamp_format)
            timestamp = utc.localize(timestamp)

            # Получаем текущее время в UTC и затем преобразуем его в локальный часовой пояс
            local_timezone = pytz.timezone("Europe/Moscow")  # Замените на ваш часовой пояс, если требуется
            current_time = datetime.now(utc).astimezone(local_timezone)

            # Приводим время обновления к локальному часовому поясу
            timestamp_local = timestamp.astimezone(local_timezone)

            # Вычисляем разницу во времени
            time_difference = current_time - timestamp_local

            # Форматируем разницу во времени
            seconds = time_difference.total_seconds()
            if seconds < 60:
                time_ago = f"{int(seconds)} секунд назад"
            elif seconds < 3600:
                minutes = seconds // 60
                time_ago = f"{int(minutes)} минут назад"
            else:
                hours = seconds // 3600
                time_ago = f"{int(hours)} часов назад"

        else:
            device_info = None
            structured_data = None
            time_ago = None

        conn.close()
    except Exception as e:
        return f"Error accessing device database: {e}", 500

    # Получаем предыдущий URL с помощью request.referrer
    previous_url = request.referrer if request.referrer else '/keys_management_view'

    # HTML-шаблон для отображения данных ключа
    template = '''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Детали ключа {{ device_info['uid'] }}</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <h1>Информация о ключе: {{ device_info['uid'] }}</h1>

            {% if device_info %}
            <table class="table table-bordered">
                <tr>
                    <th>ID</th>
                    <td>{{ device_info['id'] }}</td>
                </tr>
                <tr>
                    <th>UID</th>
                    <td>{{ device_info['uid'] }}</td>
                </tr>
                <tr>
                    <th>IP</th>
                    <td>{{ device_info['ip'] }}</td>
                </tr>
                <tr>
                    <th>Порт</th>
                    <td>{{ device_info['port'] }}</td>
                </tr>
                <tr>
                    <th>Время обновления</th>
                    <td>{{ device_info['timestamp'] }} ({{ time_ago }})</td>
                </tr>
            </table>

            {% if structured_data %}
            <h3>Основная информация</h3>
            <table class="table table-bordered">
                <tr>
                    <th>CPU Load</th>
                    <td>{{ structured_data['cpu_load'] }}</td>
                </tr>
                <tr>
                    <th>Использование памяти</th>
                    <td>{{ structured_data['memory_usage'] }}</td>
                </tr>
                <tr>
                    <th>Использование диска</th>
                    <td>{{ structured_data['disk_usage'] }}</td>
                </tr>
                <tr>
                    <th>Внутренний IP</th>
                    <td>{{ structured_data['internal_ip'] }}</td>
                </tr>
                <tr>
                    <th>Версия клиента</th>
                    <td>{{ structured_data['client_version'] }}</td>
                </tr>
                <tr>
                    <th>Статус</th>
                    <td>{{ structured_data['status'] }}</td>
                </tr>
            </table>

            <h3>Процессы</h3>
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>PID</th>
                        <th>Использование CPU</th>
                        <th>Использование памяти</th>
                        <th>Командная строка</th>
                    </tr>
                </thead>
                <tbody>
                    {% for process in structured_data['process_info'] %}
                    <tr>
                        <td>{{ process['pid'] }}</td>
                        <td>{{ process['cpu_usage'] }}</td>
                        <td>{{ process['memory_usage'] }}</td>
                        <td>{{ process['command_line'] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
                <p>Нет данных для отображения.</p>
            {% endif %}

            {% else %}
                <p>Данные по ключу не найдены.</p>
            {% endif %}

            <a href="{{ previous_url }}" class="btn btn-primary">Назад</a>
        </div>
    </body>
    </html>
    '''

    # Отображаем страницу с информацией о ключе и структурированными данными
    return render_template_string(template, device_info=device_info, structured_data=structured_data, previous_url=previous_url, time_ago=time_ago)

@app.route('/users')
@login_required
@role_required('admin')
def list_users():
    partners = User.query.filter_by(role='partner').all()
    managers = User.query.filter_by(role='manager').all()
    supervisors = User.query.filter_by(role='supervisor').all()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Пользователи</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .user-list {
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .user-list h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .user-list ul {
                list-style: none;
                padding: 0;
            }
            .user-list li {
                padding: 10px;
                border-bottom: 1px solid #ddd;
            }
            .user-list li:last-child {
                border-bottom: none;
            }
            .user-list a {
                color: #007bff;
            }
            .user-list a:hover {
                text-decoration: underline;
            }
            .btn-back {
                display: block;
                margin: 20px auto;
                width: 100px;
            }
        </style>
    </head>
    <body>
        <div class="user-list">
            <h1>Супервизоры</h1>
            <ul>
                {% for user in supervisors %}
                <li>{{ user.username }} ({{ user.tariff.name if user.tariff else 'Без тарифа' }}) - 
                    <a href="{{ url_for('edit_user', user_id=user.id) }}">Редактировать</a> - 
                    <a href="{{ url_for('delete_user', user_id=user.id) }}">Удалить</a> - 
                    <a href="{{ url_for('reset_password_admin', user_id=user.id) }}">Сбросить пароль</a></li>
                {% endfor %}
            </ul>
            <h1>Менеджеры</h1>
            <ul>
                {% for user in managers %}
                <li>{{ user.username }} ({{ user.tariff.name if user.tariff else 'Без тарифа' }}) - 
                    <a href="{{ url_for('edit_user', user_id=user.id) }}">Редактировать</a> - 
                    <a href="{{ url_for('delete_user', user_id=user.id) }}">Удалить</a> - 
                    <a href="{{ url_for('reset_password_admin', user_id=user.id) }}">Сбросить пароль</a></li>
                {% endfor %}
            </ul>
            <h1>Партнеры</h1>
            <ul>
                {% for user in partners %}
                <li>{{ user.username }} ({{ user.tariff.name if user.tariff else 'Без тарифа' }}) - 
                    <a href="{{ url_for('edit_user', user_id=user.id) }}">Редактировать</a> - 
                    <a href="{{ url_for('delete_user', user_id=user.id) }}">Удалить</a> - 
                    <a href="{{ url_for('reset_password_admin', user_id=user.id) }}">Сбросить пароль</a></li>
                {% endfor %}
            </ul>
            <a href="/admin" class="btn btn-secondary btn-back">Назад</a>
        </div>
    </body>
    </html>
    ''', partners=partners, managers=managers, supervisors=supervisors)



@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Пользователь удален')
    return redirect(url_for('list_users'))

@app.route('/reset_password_admin/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def reset_password_admin(user_id):
    user = User.query.get_or_404(user_id)
    token = secrets.token_urlsafe(16)
    user.reset_token = token
    db.session.commit()
    reset_link = url_for('reset_password_token', token=token, _external=True, scheme='https')
    if user.email:
        subject = 'Сброс пароля'
        message = f'Для сброса пароля перейдите по ссылке: {reset_link}'
        send_email(user.email, subject, message)
        flash(f'Ссылка для сброса пароля отправлена на email {user.email}')
    return redirect(url_for('list_users'))




@app.route('/supervisor')
@login_required
@role_required('supervisor')
def supervisor_dashboard():
    supervisor_id = current_user.id

    # Получение менеджеров, назначенных супервизору
    manager_associations = ManagerSupervisorAssociation.query.filter_by(supervisor_id=supervisor_id).all()
    managers = []
    for association in manager_associations:
        manager = User.query.filter_by(id=association.manager_id).first()
        if manager:
            managers.append(manager)
    
    # Получение партнёров, назначенных менеджерам
    partners = {}
    for manager in managers:
        partner_associations = PartnerManagerAssociation.query.filter_by(manager_id=manager.id).all()
        partner_list = []
        for association in partner_associations:
            partner = User.query.filter_by(id=association.partner_id).first()
            if partner:
                partner_list.append(partner)
        partners[manager.id] = partner_list

    # Получение ключей для супервизора, менеджеров и партнёров
    supervisor_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.role == 'supervisor', User.id == supervisor_id).all()
    manager_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.role == 'manager', User.id.in_([m.id for m in managers])).all()
    partner_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.role == 'partner', User.id.in_([p.id for sublist in partners.values() for p in sublist])).all()

    # Создание словаря для отображения ключей партнёров
    partner_keys_dict = {}
    for partner in [p for sublist in partners.values() for p in sublist]:
        keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(UserKey.user_id == partner.id).all()
        partner_keys_dict[partner.id] = keys

    # Подсчет устройств по статусам
    total_new_devices = len([key for key, user in partner_keys if key.status == 'new'])
    total_active_devices = len([key for key, user in partner_keys if key.status == 'active'])
    
    # Подсчет заработанных средств
    supervisor_tariff = current_user.tariff
    earnings = 0
    if supervisor_tariff:
        initial_earnings = db.session.query(Earning).filter(Earning.user_id == supervisor_id, Earning.description.like('Первоначальный заработок супервизора%')).all()
        earnings = sum(e.amount for e in initial_earnings)

    # Получение информации о начислениях
    earnings_data = db.session.query(Earning).filter(Earning.user_id == supervisor_id).all()
    earnings_summary = sum(e.amount for e in earnings_data)
    percentage_earnings = earnings_summary - earnings

    # Получение тарифов, назначенных пользователям
    assigned_tariff_ids = {user.tariff_id for user in managers + [current_user] if user.tariff_id is not None}
    assigned_tariffs = Tariff.query.filter(Tariff.id.in_(assigned_tariff_ids)).all()

    # Вычисление остатка дней
    def calculate_days_left(end_date):
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%м-%д %H:%М:%S')
                return (end_date - datetime.now()).days
            except ValueError:
                return None
        return None

    # Обновление описания начислений
    for earning in earnings_data:
        key = UserKey.query.filter_by(id=earning.key_id).first()
        if key and key.tariff_id:
            tariff = Tariff.query.filter_by(id=key.tariff_id).first()
            if tariff:
                try:
                    start_date = datetime.strptime(key.start_date, '%Y-%м-%д %H:%М:%S')
                    end_date = datetime.strptime(key.end_date, '%Y-%м-%д %H:%М:%С')
                    duration_days = (end_date - start_date).days
                    new_description = f'{earning.description} за {duration_days} дней, с {start_date.strftime("%Y-%м-%д")} по {end_date.strftime("%Y-%м-%д")}, по тарифу {tariff.name}'
                    earning.description = new_description
                    db.session.add(earning)
                    db.session.commit()
                except ValueError:
                    pass

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Панель супервизора</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .dashboard {
                max-width: 1000px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .dashboard h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .nav-tabs {
                margin-bottom: 20px;
            }
            .tab-content {
                margin-top: 20px;
            }
            .keys-container {
                margin-top: 20px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            table, th, td {
                border: 1px solid #ddd;
            }
            th, td {
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
            .manager-header {
                font-size: 16px;
                color: #6c757d;
                margin-top: 10px;
                margin-bottom: 10px;
            }
            .dashboard a {
                display: block;
                margin: 10px 0;
                padding: 10px;
                background-color: #007bff;
                color: white;
                text-align: center;
                border-radius: 4px;
                text-decoration: none;
            }
            .dashboard a:hover {
                background-color: #0056b3;
            }
            .btn-secondary {
                display: block;
                margin: 20px auto;
                padding: 10px 20px;
                background-color: #6c757d;
                color: white;
                text-align: center;
                border-radius: 4px;
                text-decoration: none;
            }
            .nav-item .active {
                background-color: #007bff !important;
                color: white !important;
            }
            .nav-link {
                cursor: pointer;
                color: #007bff;
            }
            .nav-link:hover {
                color: #0056b3;
            }
            .btn-status {
                background-color: #007bff;
                color: white;
                margin: 2px;
                border-radius: 4px;
                padding: 5px 10px;
                cursor: pointer;
                border: none;
            }
            .btn-status.active {
                background-color: #0056b3;
                color: white;
            }
            .btn-status:hover {
                background-color: #0056b3;
            }
            .summary {
                margin-top: 20px;
                font-size: 16px;
            }
            .partner-info {
                border-top: 1px solid #ddd;
                padding-top: 10px;
                margin-top: 10px;
            }
        </style>
        <script>
            function togglePartnerKeys(partnerId, status) {
                var keys = document.querySelectorAll('.key-row[data-partner="' + partnerId + '"]');
                keys.forEach(function(key) {
                    if (status === 'all' || key.dataset.status === status) {
                        key.style.display = '';
                    } else {
                        key.style.display = 'none';
                    }
                });

                var tabs = document.querySelectorAll('.nav-item a[data-partner="' + partnerId + '"]');
                tabs.forEach(function(tab) {
                    tab.classList.remove('active');
                });
                document.querySelector('.nav-item a[data-partner="' + partnerId + '"][data-status="' + status + '"]').classList.add('active');
            }

            // Prevent page scroll on tab change
            document.addEventListener('DOMContentLoaded', function() {
                var links = document.querySelectorAll('.nav-link');
                links.forEach(function(link) {
                    link.addEventListener('click', function(event) {
                        event.preventDefault();
                    });
                });

                // Add click event to status buttons
                var statusButtons = document.querySelectorAll('.btn-status');
                statusButtons.forEach(function(button) {
                    button.addEventListener('click', function() {
                        var partnerId = button.dataset.partner;
                        var status = button.dataset.status;
                        togglePartnerKeys(partnerId, status);
                        
                        // Remove active class from all buttons
                        var buttons = document.querySelectorAll('.btn-status[data-partner="' + partnerId + '"]');
                        buttons.forEach(function(btn) {
                            btn.classList.remove('active');
                        });

                        // Add active class to clicked button
                        button.classList.add('active');
                    });
                });
            });
        </script>
    </head>
    <body>
        <div class="dashboard">
            <h1>Панель супервизора</h1>
            <ul class="nav nav-tabs" id="myTab" role="tablist">
                <li class="nav-item">
                    <a class="nav-link active" id="managers-tab" data-toggle="tab" href="#managers" role="tab" aria-controls="managers" aria-selected="true">Менеджеры</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" id="keys-tab" data-toggle="tab" href="#keys" role="tab" aria-controls="keys" aria-selected="false">Ключи</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" id="tariffs-tab" data-toggle="tab" href="#tariffs" role="tab" aria-controls="tariffs" aria-selected="false">Тарифы</a>
                </li>
            </ul>
            <div class="tab-content" id="myTabContent">
                <div class="tab-pane fade show active" id="managers" role="tabpanel" aria-labelledby="managers-tab">
                    <h2>Назначенные менеджеры</h2>
                    {% for manager in managers %}
                    <div class="manager-header">{{ manager.username }}</div>
                    <h4>Партнёры:</h4>
                    <table class="table table-striped">
                        <thead class="thead-dark">
                            <tr>
                                <th>Партнёр</th>
                                <th>Информация</th>
                                <th>Ключи</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for partner in partners[manager.id] %}
                            <tr class="partner-info">
                                <td>{{ partner.username }}</td>
                                <td>
                                    <p>Email: {{ partner.email }}</p>
                                    <p>Телефон: {{ partner.phone }}</p>
                                    <p>Адрес: {{ partner.address }}</p>
                                    <p>Примечание: {{ partner.notes }}</p>
                                </td>
                                <td>
                                    <div class="btn-group" role="group" aria-label="Status buttons">
                                        <button type="button" class="btn-status" data-partner="{{ partner.id }}" data-status="new" onclick="togglePartnerKeys({{ partner.id }}, 'new')">New</button>
                                        <button type="button" class="btn-status active" data-partner="{{ partner.id }}" data-status="active" onclick="togglePartnerKeys({{ partner.id }}, 'active')">Active</button>
                                        <button type="button" class="btn-status" data-partner="{{ partner.id }}" data-status="all" onclick="togglePartnerKeys({{ partner.id }}, 'all')">All</button>
                                    </div>
                                    <table class="table table-striped">
                                        <thead class="thead-dark">
                                            <tr>
                                                <th>Ключ</th>
                                                <th>Статус</th>
                                                <th>Дата начала</th>
                                                <th>Дата окончания</th>
                                                <th>Дней</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% for key, user in partner_keys_dict[partner.id] %}
                                            <tr class="key-row" data-partner="{{ partner.id }}" data-status="{{ key.status }}">
                                                <td>{{ key.key }}</td>
                                                <td>{{ key.status }}</td>
                                                <td>{{ key.start_date }}</td>
                                                <td>{{ key.end_date }}</td>
                                                <td>{{ calculate_days_left(key.end_date) }}</td>
                                            </tr>
                                            {% endfor %}
                                        </tbody>
                                    </table>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% endfor %}
                </div>
                <div class="tab-pane fade" id="keys" role="tabpanel" aria-labelledby="keys-tab">
                    <h2>Ключи, закрепленные за ролями</h2>
                    <div class="keys-container">
                        <h3>Ключи супервизора</h3>
                        <table class="table table-striped">
                            <thead class="thead-dark">
                                <tr>
                                    <th>Ключ</th>
                                    <th>Статус</th>
                                    <th>Дата начала</th>
                                    <th>Дата окончания</th>
                                    <th>Остаток дней</th>
                                    <th>Партнёр</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for key, user in supervisor_keys %}
                                <tr>
                                    <td>{{ key.key }}</td>
                                    <td>{{ key.status }}</td>
                                    <td>{{ key.start_date }}</td>
                                    <td>{{ key.end_date }}</td>
                                    <td>{{ calculate_days_left(key.end_date) }}</td>
                                    <td>{{ user.username }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        <h3>Ключи менеджеров</h3>
                        <table class="table table-striped">
                            <thead class="thead-dark">
                                <tr>
                                    <th>Ключ</th>
                                    <th>Статус</th>
                                    <th>Дата начала</th>
                                    <th>Дата окончания</th>
                                    <th>Остаток дней</th>
                                    <th>Партнёр</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for key, user in manager_keys %}
                                <tr>
                                    <td>{{ key.key }}</td>
                                    <td>{{ key.status }}</td>
                                    <td>{{ key.start_date }}</td>
                                    <td>{{ key.end_date }}</td>
                                    <td>{{ calculate_days_left(key.end_date) }}</td>
                                    <td>{{ user.username }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        <h3>Ключи партнёров</h3>
                        <table class="table table-striped">
                            <thead class="thead-dark">
                                <tr>
                                    <th>Ключ</th>
                                    <th>Статус</th>
                                    <th>Дата начала</th>
                                    <th>Дата окончания</th>
                                    <th>Остаток дней</th>
                                    <th>Партнёр</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for key, user in partner_keys %}
                                <tr>
                                    <td>{{ key.key }}</td>
                                    <td>{{ key.status }}</td>
                                    <td>{{ key.start_date }}</td>
                                    <td>{{ key.end_date }}</td>
                                    <td>{{ calculate_days_left(key.end_date) }}</td>
                                    <td>{{ user.username }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
                <div class="tab-pane fade" id="tariffs" role="tabpanel" aria-labelledby="tariffs-tab">
                    <h2>Тарифы</h2>
                    <table class="table table-striped table-sm">
                        <thead class="thead-dark">
                            <tr>
                                <th>ID</th>
                                <th>Название</th>
                                <th>Базовая цена</th>
                                <th>Партнёрская оплата</th>
                                <th>Менеджерская оплата</th>
                                <th>Оплата супервизора</th>
                                <th>% подписки партнёра</th>
                                <th>% подписки менеджера</th>
                                <th>% подписки супервизора</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for tariff in assigned_tariffs %}
                            <tr>
                                <td>{{ tariff.id }}</td>
                                <td>{{ tariff.name }}</td>
                                <td>{{ tariff.base_price }}</td>
                                <td>{{ tariff.partner_initial_payment }}</td>
                                <td>{{ tariff.manager_initial_payment }}</td>
                                <td>{{ tariff.supervisor_initial_payment }}</td>
                                <td>{{ tariff.partner_subscription_percentage }}</td>
                                <td>{{ tariff.manager_subscription_percentage }}</td>
                                <td>{{ tariff.supervisor_subscription_percentage }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    <div class="summary">
                        <p>Всего неактивных устройств: {{ total_new_devices }}</p>
                        <p>Всего активных устройств: {{ total_active_devices }}</p>
                        <p>Заработано с продажи: {{ earnings }}</p>
                        <p>Сумма начисленного процента: {{ percentage_earnings }}</p>
                        <p>Всего начислено: {{ earnings_summary }}</p>
                    </div>
                    <h2>История начислений</h2>
                    <table class="table table-striped">
                        <thead class="thead-dark">
                            <tr>
                                <th>ID</th>
                                <th>Ключ</th>
                                <th>Пользователь</th>
                                <th>Сумма</th>
                                <th>Дата</th>
                                <th>Описание</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for earning in earnings_data %}
                            <tr>
                                <td>{{ earning.id }}</td>
                                <td>{{ earning.key_id }}</td>
                                <td>{{ earning.user.username }}</td>
                                <td>{{ earning.amount }}</td>
                                <td>{{ earning.date }}</td>
                                <td>{{ earning.description }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            <a href="/logout" class="btn btn-secondary">Выйти</a>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    </body>
    </html>
    ''', managers=managers, partners=partners, supervisor_keys=supervisor_keys, manager_keys=manager_keys, partner_keys=partner_keys, partner_keys_dict=partner_keys_dict, assigned_tariffs=assigned_tariffs, total_new_devices=total_new_devices, total_active_devices=total_active_devices, earnings=earnings, earnings_data=earnings_data, earnings_summary=earnings_summary, percentage_earnings=percentage_earnings, calculate_days_left=calculate_days_left)


@app.route('/partner')
@login_required
@role_required('partner')
def partner_dashboard():
    partner_id = current_user.id

    # Получение менеджера, назначенного партнёру
    manager_association = PartnerManagerAssociation.query.filter_by(partner_id=partner_id).first()
    manager = User.query.filter_by(id=manager_association.manager_id).first() if manager_association else None

    # Получение супервизора, назначенного менеджеру
    supervisor = None
    if manager:
        supervisor_association = ManagerSupervisorAssociation.query.filter_by(manager_id=manager.id).first()
        supervisor = User.query.filter_by(id=supervisor_association.supervisor_id).first() if supervisor_association else None

    # Получение ключей для партнёра
    partner_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.role == 'partner', User.id == partner_id).all()

    # Подсчет устройств по статусам
    total_new_devices = len([key for key, user in partner_keys if key.status == 'new'])
    total_active_devices = len([key for key, user in partner_keys if key.status == 'active'])
    
    # Подсчет заработанных средств
    partner_tariff = current_user.tariff
    earnings = 0
    if partner_tariff:
        initial_earnings = db.session.query(Earning).filter(Earning.user_id == partner_id, Earning.description.like('Первоначальный заработок партнёра%')).all()
        earnings = sum(e.amount for e in initial_earnings)

    # Получение информации о начислениях
    earnings_data = db.session.query(Earning).filter(Earning.user_id == partner_id).all()
    earnings_summary = sum(e.amount for e in earnings_data)

    # Получение тарифов, назначенных пользователю
    assigned_tariffs = []
    if partner_tariff:
        assigned_tariffs.append(partner_tariff)

    # Вычисление остатка дней
    def calculate_days_left(end_date):
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d %H:%M:%S')
            return (end_date - datetime.now()).days
        return None

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Панель партнёра</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .dashboard {
                max-width: 1000px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .dashboard h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .nav-tabs {
                margin-bottom: 20px;
            }
            .tab-content {
                margin-top: 20px;
            }
            .keys-container {
                margin-top: 20px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            table, th, td {
                border: 1px solid #ddd;
            }
            th, td {
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
            .manager-header {
                font-size: 16px;
                color: #6c757d;
                margin-top: 10px;
                margin-bottom: 10px;
            }
            .dashboard a {
                display: block;
                margin: 10px 0;
                padding: 10px;
                background-color: #007bff;
                color: white;
                text-align: center;
                border-radius: 4px;
                text-decoration: none;
            }
            .dashboard a:hover {
                background-color: #0056b3;
            }
            .btn-secondary {
                display: block;
                margin: 20px auto;
                padding: 10px 20px;
                background-color: #6c757d;
                color: white;
                text-align: center;
                border-radius: 4px;
                text-decoration: none;
            }
            .nav-item .active {
                background-color: #007bff !important;
                color: white !important;
            }
            .nav-link {
                cursor: pointer;
                color: #007bff;
            }
            .nav-link:hover {
                color: #0056b3;
            }
            .btn-status {
                background-color: #007bff;
                color: white;
                margin: 2px;
                border-radius: 4px;
                padding: 5px 10px;
                cursor: pointer;
                border: none;
            }
            .btn-status.active {
                background-color: #0056b3;
                color: white;
            }
            .btn-status:hover {
                background-color: #0056b3;
            }
            .summary {
                margin-top: 20px;
                font-size: 16px;
            }
        </style>
        <script>
            function togglePartnerKeys(status) {
                var keys = document.querySelectorAll('.key-row');
                keys.forEach(function(key) {
                    if (status === 'all' || key.dataset.status === status) {
                        key.style.display = '';
                    } else {
                        key.style.display = 'none';
                    }
                });

                var tabs = document.querySelectorAll('.nav-item a');
                tabs.forEach(function(tab) {
                    tab.classList.remove('active');
                });
                document.querySelector('.nav-item a[data-status="' + status + '"]').classList.add('active');
            }

            // Prevent page scroll on tab change
            document.addEventListener('DOMContentLoaded', function() {
                var links = document.querySelectorAll('.nav-link');
                links.forEach(function(link) {
                    link.addEventListener('click', function(event) {
                        event.preventDefault();
                    });
                });

                // Add click event to status buttons
                var statusButtons = document.querySelectorAll('.btn-status');
                statusButtons.forEach(function(button) {
                    button.addEventListener('click', function() {
                        var status = button.dataset.status;
                        togglePartnerKeys(status);
                        
                        // Remove active class from all buttons
                        var buttons = document.querySelectorAll('.btn-status');
                        buttons.forEach(function(btn) {
                            btn.classList.remove('active');
                        });

                        // Add active class to clicked button
                        button.classList.add('active');
                    });
                });
            });
        </script>
    </head>
    <body>
        <div class="dashboard">
            <h1>Панель партнёра</h1>
            <ul class="nav nav-tabs" id="myTab" role="tablist">
                <li class="nav-item">
                    <a class="nav-link active" id="manager-tab" data-toggle="tab" href="#manager" role="tab" aria-controls="manager" aria-selected="true">Менеджер</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" id="keys-tab" data-toggle="tab" href="#keys" role="tab" aria-controls="keys" aria-selected="false">Ключи</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" id="tariffs-tab" data-toggle="tab" href="#tariffs" role="tab" aria-controls="tariffs" aria-selected="false">Тарифы</a>
                </li>
            </ul>
            <div class="tab-content" id="myTabContent">
                <div class="tab-pane fade show active" id="manager" role="tabpanel" aria-labelledby="manager-tab">
                    <h2>Менеджер</h2>
                    {% if manager %}
                    <p>Менеджер: {{ manager.username }}</p>
                    <p>Email: {{ manager.email }}</p>
                    {% else %}
                    <p>Менеджер не назначен.</p>
                    {% endif %}
                    <h2>Супервизор</h2>
                    {% if supervisor %}
                    <p>Супервизор: {{ supervisor.username }}</p>
                    <p>Email: {{ supervisor.email }}</p>
                    {% else %}
                    <p>Супервизор не назначен.</p>
                    {% endif %}
                </div>
                <div class="tab-pane fade" id="keys" role="tabpanel" aria-labelledby="keys-tab">
                    <h2>Ключи</h2>
                    <div class="btn-group" role="group" aria-label="Status buttons">
                        <button type="button" class="btn-status" data-status="new" onclick="togglePartnerKeys('new')">New</button>
                        <button type="button" class="btn-status active" data-status="active" onclick="togglePartnerKeys('active')">Active</button>
                        <button type="button" class="btn-status" data-status="all" onclick="togglePartnerKeys('all')">All</button>
                    </div>
                    <table class="table table-striped">
                        <thead class="thead-dark">
                            <tr>
                                <th>Ключ</th>
                                <th>Статус</th>
                                <th>Дата начала</th>
                                <th>Дата окончания</th>
                                <th>Остаток дней</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for key, user in partner_keys %}
                            <tr class="key-row" data-status="{{ key.status }}">
                                <td>{{ key.key }}</td>
                                <td>{{ key.status }}</td>
                                <td>{{ key.start_date }}</td>
                                <td>{{ key.end_date }}</td>
                                <td>{{ calculate_days_left(key.end_date) }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                <div class="tab-pane fade" id="tariffs" role="tabpanel" aria-labelledby="tariffs-tab">
                    <h2>Тарифы</h2>
                    <table class="table table-striped table-sm">
                        <thead class="thead-dark">
                            <tr>
                                <th>ID</th>
                                <th>Название</th>
                                <th>Базовая цена</th>
                                <th>Партнёрская оплата</th>
                                <th>Процент подписки партнёра</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for tariff in assigned_tariffs %}
                            <tr>
                                <td>{{ tariff.id }}</td>
                                <td>{{ tariff.name }}</td>
                                <td>{{ tariff.base_price }}</td>
                                <td>{{ tariff.partner_initial_payment }}</td>
                                <td>{{ tariff.partner_subscription_percentage }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    <div class="summary">
                        <p>Всего неактивных устройств: {{ total_new_devices }}</p>
                        <p>Всего активных устройств: {{ total_active_devices }}</p>
                        <p>Заработано с продажи: {{ earnings }}</p>
                        <p>Всего начислено: {{ earnings_summary }}</p>
                    </div>
                    <h2>История начислений</h2>
                    <table class="table table-striped">
                        <thead class="thead-dark">
                            <tr>
                                <th>ID</th>
                                <th>Ключ</th>
                                <th>Пользователь</th>
                                <th>Сумма</th>
                                <th>Дата</th>
                                <th>Описание</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for earning in earnings_data %}
                            <tr>
                                <td>{{ earning.id }}</td>
                                <td>{{ earning.key_id }}</td>
                                <td>{{ earning.user.username }}</td>
                                <td>{{ earning.amount }}</td>
                                <td>{{ earning.date }}</td>
                                <td>{{ earning.description }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            <a href="/logout" class="btn btn-secondary">Выйти</a>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    </body>
    </html>
    ''', manager=manager, supervisor=supervisor, partner_keys=partner_keys, assigned_tariffs=assigned_tariffs, total_new_devices=total_new_devices, total_active_devices=total_active_devices, earnings=earnings, earnings_data=earnings_data, earnings_summary=earnings_summary, calculate_days_left=calculate_days_left)



@app.route('/manager')
@login_required
@role_required('manager')
def manager_dashboard():
    manager_id = current_user.id

    # Получение супервизора, назначенного менеджеру
    supervisor_association = ManagerSupervisorAssociation.query.filter_by(manager_id=manager_id).first()
    supervisor = User.query.filter_by(id=supervisor_association.supervisor_id).first() if supervisor_association else None

    # Получение партнёров, назначенных менеджеру
    partner_associations = PartnerManagerAssociation.query.filter_by(manager_id=manager_id).all()
    partners = [User.query.filter_by(id=association.partner_id).first() for association in partner_associations]

    # Получение ключей для менеджера и его партнёров
    manager_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.role == 'manager', User.id == manager_id).all()
    partner_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.role == 'partner', User.id.in_([p.id for p in partners])).all()

    # Создание словаря для отображения ключей партнёров
    partner_keys_dict = {}
    for partner in partners:
        keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(UserKey.user_id == partner.id).all()
        partner_keys_dict[partner.id] = keys

    # Подсчет устройств по статусам
    total_new_devices = len([key for key, user in partner_keys if key.status == 'new'])
    total_active_devices = len([key for key, user in partner_keys if key.status == 'active'])
    
    # Подсчет заработанных средств
    manager_tariff = current_user.tariff
    earnings = 0
    if manager_tariff:
        initial_earnings = db.session.query(Earning).filter(Earning.user_id == manager_id, Earning.description.like('Первоначальный заработок менеджера%')).all()
        earnings = sum(e.amount for e in initial_earnings)

    # Получение информации о начислениях
    earnings_data = db.session.query(Earning).filter(Earning.user_id == manager_id).all()
    earnings_summary = sum(e.amount for e in earnings_data)

    # Получение тарифов, назначенных пользователю
    assigned_tariffs = []
    if manager_tariff:
        assigned_tariffs.append(manager_tariff)

    # Вычисление остатка дней
    def calculate_days_left(end_date):
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d %H:%M:%S')
            return (end_date - datetime.now()).days
        return None

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Панель менеджера</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .dashboard {
                max-width: 1000px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .dashboard h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .nav-tabs {
                margin-bottom: 20px;
            }
            .tab-content {
                margin-top: 20px;
            }
            .keys-container {
                margin-top: 20px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            table, th, td {
                border: 1px solid #ddd;
            }
            th, td {
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
            .manager-header {
                font-size: 16px;
                color: #6c757d;
                margin-top: 10px;
                margin-bottom: 10px;
            }
            .dashboard a {
                display: block;
                margin: 10px 0;
                padding: 10px;
                background-color: #007bff;
                color: white;
                text-align: center;
                border-radius: 4px;
                text-decoration: none;
            }
            .dashboard a:hover {
                background-color: #0056b3;
            }
            .btn-secondary {
                display: block;
                margin: 20px auto;
                padding: 10px 20px;
                background-color: #6c757d;
                color: white;
                text-align: center;
                border-radius: 4px;
                text-decoration: none;
            }
            .nav-item .active {
                background-color: #007bff !important;
                color: white !important;
            }
            .nav-link {
                cursor: pointer;
                color: #007bff;
            }
            .nav-link:hover {
                color: #0056b3;
            }
            .btn-status {
                background-color: #007bff;
                color: white;
                margin: 2px;
                border-radius: 4px;
                padding: 5px 10px;
                cursor: pointer;
                border: none;
            }
            .btn-status.active {
                background-color: #0056b3;
                color: white;
            }
            .btn-status:hover {
                background-color: #0056b3;
            }
            .summary {
                margin-top: 20px;
                font-size: 16px;
            }
            .partner-info {
                border-top: 1px solid #ddd;
                padding-top: 10px;
                margin-top: 10px;
                padding-bottom: 10px;
            }
            .partner-keys {
                margin-top: 10px;
            }
        </style>
        <script>
            function togglePartnerKeys(partnerId, status) {
                var keys = document.querySelectorAll('.key-row[data-partner="' + partnerId + '"]');
                keys.forEach(function(key) {
                    if (status === 'all' || key.dataset.status === status) {
                        key.style.display = '';
                    } else {
                        key.style.display = 'none';
                    }
                });

                var tabs = document.querySelectorAll('.nav-item a[data-partner="' + partnerId + '"]');
                tabs.forEach(function(tab) {
                    tab.classList.remove('active');
                });
                document.querySelector('.nav-item a[data-partner="' + partnerId + '"][data-status="' + status + '"]').classList.add('active');
            }

            // Prevent page scroll on tab change
            document.addEventListener('DOMContentLoaded', function() {
                var links = document.querySelectorAll('.nav-link');
                links.forEach(function(link) {
                    link.addEventListener('click', function(event) {
                        event.preventDefault();
                    });
                });

                // Add click event to status buttons
                var statusButtons = document.querySelectorAll('.btn-status');
                statusButtons.forEach(function(button) {
                    button.addEventListener('click', function() {
                        var partnerId = button.dataset.partner;
                        var status = button.dataset.status;
                        togglePartnerKeys(partnerId, status);
                        
                        // Remove active class from all buttons
                        var buttons = document.querySelectorAll('.btn-status[data-partner="' + partnerId + '"]');
                        buttons.forEach(function(btn) {
                            btn.classList.remove('active');
                        });

                        // Add active class to clicked button
                        button.classList.add('active');
                    });
                });
            });
        </script>
    </head>
    <body>
        <div class="dashboard">
            <h1>Панель менеджера</h1>
            <ul class="nav nav-tabs" id="myTab" role="tablist">
                <li class="nav-item">
                    <a class="nav-link active" id="supervisor-tab" data-toggle="tab" href="#supervisor" role="tab" aria-controls="supervisor" aria-selected="true">Супервизор</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" id="partners-tab" data-toggle="tab" href="#partners" role="tab" aria-controls="partners" aria-selected="false">Партнёры</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" id="tariffs-tab" data-toggle="tab" href="#tariffs" role="tab" aria-controls="tariffs" aria-selected="false">Тарифы</a>
                </li>
            </ul>
            <div class="tab-content" id="myTabContent">
                <div class="tab-pane fade show active" id="supervisor" role="tabpanel" aria-labelledby="supervisor-tab">
                    <h2>Супервизор</h2>
                    {% if supervisor %}
                    <p>Супервизор: {{ supervisor.username }}</p>
                    <p>Email: {{ supervisor.email }}</p>
                    {% else %}
                    <p>Супервизор не назначен.</p>
                    {% endif %}
                </div>
                <div class="tab-pane fade" id="partners" role="tabpanel" aria-labelledby="partners-tab">
                    <h2>Назначенные партнёры</h2>
                    {% for partner in partners %}
                    <div class="partner-info">
                        <div class="manager-header">{{ partner.username }}</div>
                        <p>Email: {{ partner.email }}</p>
                        <p>Телефон: {{ partner.phone }}</p>
                        <p>Адрес: {{ partner.address }}</p>
                        <p>Примечание: {{ partner.notes }}</p>
                        <div class="btn-group" role="group" aria-label="Status buttons">
                            <button type="button" class="btn-status" data-partner="{{ partner.id }}" data-status="new" onclick="togglePartnerKeys({{ partner.id }}, 'new')">New</button>
                            <button type="button" class="btn-status active" data-partner="{{ partner.id }}" data-status="active" onclick="togglePartnerKeys({{ partner.id }}, 'active')">Active</button>
                            <button type="button" class="btn-status" data-partner="{{ partner.id }}" data-status="all" onclick="togglePartnerKeys({{ partner.id }}, 'all')">All</button>
                        </div>
                        <div class="partner-keys">
                            <h4>Ключи:</h4>
                            <table class="table table-striped">
                                <thead class="thead-dark">
                                    <tr>
                                        <th>Ключ</th>
                                        <th>Статус</th>
                                        <th>Дата начала</th>
                                        <th>Дата окончания</th>
                                        <th>Остаток дней</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for key, user in partner_keys_dict[partner.id] %}
                                    <tr class="key-row" data-partner="{{ partner.id }}" data-status="{{ key.status }}">
                                        <td>{{ key.key }}</td>
                                        <td>{{ key.status }}</td>
                                        <td>{{ key.start_date }}</td>
                                        <td>{{ key.end_date }}</td>
                                        <td>{{ calculate_days_left(key.end_date) }}</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    {% endfor %}
                </div>
                <div class="tab-pane fade" id="tariffs" role="tabpanel" aria-labelledby="tariffs-tab">
                    <h2>Тарифы</h2>
                    <table class="table table-striped table-sm">
                        <thead class="thead-dark">
                            <tr>
                                <th>ID</th>
                                <th>Название</th>
                                <th>Базовая цена</th>
                                <th>Партнёрская оплата</th>
                                <th>Менеджерская оплата</th>
                                <th>% подписки партнёра</th>
                                <th>% подписки менеджера</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for tariff in assigned_tariffs %}
                            <tr>
                                <td>{{ tariff.id }}</td>
                                <td>{{ tariff.name }}</td>
                                <td>{{ tariff.base_price }}</td>
                                <td>{{ tariff.partner_initial_payment }}</td>
                                <td>{{ tariff.manager_initial_payment }}</td>
                                <td>{{ tariff.partner_subscription_percentage }}</td>
                                <td>{{ tariff.manager_subscription_percentage }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    <div class="summary">
                        <p>Всего неактивных устройств: {{ total_new_devices }}</p>
                        <p>Всего активных устройств: {{ total_active_devices }}</p>
                        <p>Заработано с продажи: {{ earnings }}</p>
                        <p>Всего начислено: {{ earnings_summary }}</p>
                    </div>
                    <h2>История начислений</h2>
                    <table class="table table-striped">
                        <thead class="thead-dark">
                            <tr>
                                <th>ID</th>
                                <th>Ключ</th>
                                <th>Пользователь</th>
                                <th>Сумма</th>
                                <th>Дата</th>
                                <th>Описание</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for earning in earnings_data %}
                            <tr>
                                <td>{{ earning.id }}</td>
                                <td>{{ earning.key_id }}</td>
                                <td>{{ earning.user.username }}</td>
                                <td>{{ earning.amount }}</td>
                                <td>{{ earning.date }}</td>
                                <td>{{ earning.description }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            <a href="/logout" class="btn btn-secondary">Выйти</a>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    </body>
    </html>
    ''', supervisor=supervisor, partners=partners, manager_keys=manager_keys, partner_keys=partner_keys, partner_keys_dict=partner_keys_dict, assigned_tariffs=assigned_tariffs, total_new_devices=total_new_devices, total_active_devices=total_active_devices, earnings=earnings, earnings_data=earnings_data, earnings_summary=earnings_summary, calculate_days_left=calculate_days_left)



# Подключение к базе данных и получение данных в зависимости от роли пользователя
def get_data_for_user(role):
    conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
    if role == 'admin':
        users = pd.read_sql_query("SELECT id, email, password FROM users", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data", conn)
    elif role == 'partner':
        users = pd.read_sql_query("SELECT id, email, password FROM users WHERE role = 'partner'", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs WHERE user_id IN (SELECT id FROM users WHERE role = 'partner')", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys WHERE user_id IN (SELECT id FROM users WHERE role = 'partner')", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data WHERE user_id IN (SELECT id FROM users WHERE role = 'partner')", conn)
    elif role == 'manager':
        users = pd.read_sql_query("SELECT id, email, password FROM users WHERE role = 'manager'", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs WHERE user_id IN (SELECT id FROM users WHERE role = 'manager')", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys WHERE user_id IN (SELECT id FROM users WHERE role = 'manager')", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data WHERE user_id IN (SELECT id FROM users WHERE role = 'manager')", conn)
    else:
        users = pd.read_sql_query("SELECT id, email, password FROM users", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data", conn)

    conn.close()
    return users, user_tariffs, tariffs, user_keys, miner_data







@app.route('/keys_management', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def keys_management_view():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    start_date = request.args.get('start_date') if request.method == 'GET' else request.form.get('start_date')

    role = current_user.role
    users, user_tariffs, tariffs, user_keys, miner_data = get_data_for_user(role)

    # Объединение данных ключей с тарифами
    user_keys_with_tariffs = user_keys.merge(tariffs, left_on='tariff_id', right_on='tariff_id', how='left', suffixes=('', '_tariffs'))

    # Объединение данных пользователей с ключами
    merged_data = users.merge(user_keys_with_tariffs, left_on='id', right_on='user_id', how='left', suffixes=('', '_user_keys'))

    # Проверка наличия столбца 'key_name' и заполнение NaN значений
    if 'key_name' in merged_data.columns:
        merged_data['key_name'].fillna('Без названия', inplace=True)
    else:
        merged_data['key_name'] = 'Без названия'

    merged_data['start_date'].fillna('N/A', inplace=True)
    merged_data['end_date'].fillna('N/A', inplace=True)
    merged_data['status'].fillna('N/A', inplace=True)
    merged_data['name'].fillna('Без тарифа', inplace=True)

    # Форматирование данных для отображения
    merged_data['start_date'] = merged_data['start_date'].apply(lambda x: pd.to_datetime(x).strftime('%Y-%m-%d %H:%M:%S') if x != 'N/A' else x)
    merged_data['end_date'] = merged_data['end_date'].apply(lambda x: pd.to_datetime(x).strftime('%Y-%m-%d %H:%M:%S') if x != 'N/A' else x)

    # Преобразование данных в словарь, где ключ - это email пользователя, а значение - DataFrame с информацией о ключах
    user_keys_dict = merged_data.groupby('email').apply(lambda x: x[['key', 'key_name', 'start_date', 'end_date', 'status', 'name']].to_dict(orient='records')).to_dict()

    # Пагинация
    total = len(user_keys_dict)
    start = (page - 1) * per_page
    end = start + per_page if per_page != -1 else total
    paginated_user_keys_dict = dict(list(user_keys_dict.items())[start:end])

    # Шаблон для отображения таблицы
    template = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keys Management</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://code.jquery.com/ui/1.12.1/themes/base/jquery-ui.css">
    <style>
        body {
            padding: 20px;
            background-color: #f7f7f7;
            font-family: Arial, sans-serif;
        }
        h1 {
            text-align: center;
            margin-bottom: 20px;
        }
        .filter-container {
            margin-bottom: 20px;
            text-align: center;
        }
        .filter-container input {
            margin: 5px;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            width: 200px; /* Увеличение ширины полей фильтра */
        }
        .table-container {
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .keys-table {
            margin-top: 20px;
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 6px; /* Сужение горизонтальных столбцов */
            text-align: left;
            vertical-align: top;
            white-space: nowrap; /* Убрать перенос */
        }
        th {
            background-color: #f2f2f2;
            cursor: pointer;
            position: relative;
        }
        th.sorted-asc::after, th.sorted-desc::after {
            content: "";
            position: absolute;
            right: 8px;
        }
        th.sorted-asc::after {
            content: "▲";
        }
        th.sorted-desc::after {
            content: "▼";
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .pagination {
            display: flex;
            justify-content: center;
            padding: 20px 0;
        }
        .pagination a {
            margin: 0 10px;
            padding: 8px 16px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }
        .pagination a:hover {
            background-color: #0056b3;
        }
        .pagination .active {
            background-color: #0056b3;
            pointer-events: none;
        }
        .totals-row {
            font-weight: bold;
            background-color: #f9f9f9;
        }
        .key-entry {
            margin-bottom: 10px;
            padding: 8px; /* Увеличение паддинга */
            border-bottom: 1px solid #ddd;
        }
        .show-all {
            margin: 20px 0;
            text-align: center;
        }
        .key-name-column, .date-column {
            width: 220px; /* Увеличение ширины для столбцов с названиями ключей и датами */
        }
        .email-column, .status-column, .tariff-column, .login-column {
            width: 120px; /* Уменьшение ширины для других столбцов */
        }
        .login-btn {
            padding: 6px 12px;
            background-color: #28a745;
            color: white;
            border: none;
            border-radius: 4px;
            text-align: center;
            cursor: pointer;
        }
        .login-btn:hover {
            background-color: #218838;
        }
    </style>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://code.jquery.com/ui/1.12.1/jquery-ui.js"></script>
    <script>
        $(function() {
            $("#start_date").datepicker({
                dateFormat: 'yy-mm-dd',
                onSelect: function(dateText) {
                    $("#dateForm").submit();
                }
            });

            const filterInputs = document.querySelectorAll('.filter-container input');
            filterInputs.forEach(input => input.addEventListener('keyup', filterTable));
        });

        let currentSortColumn = -1;
        let currentSortDirection = "asc";

        function sortTable(columnIndex, isNumeric = false) {
            const table = document.getElementById("summaryTable");
            const tbody = table.querySelector("tbody");
            let rows = Array.from(tbody.querySelectorAll("tr:not(.totals-row)"));
            const totalsRow = tbody.querySelector(".totals-row");

            if (columnIndex === currentSortColumn) {
                currentSortDirection = currentSortDirection === "asc" ? "desc" : "asc";
            } else {
                currentSortColumn = columnIndex;
                currentSortDirection = "asc";
            }
            updateSortIndicators();

            rows.sort((a, b) => {
                let valA = a.children[columnIndex].textContent;
                let valB = b.children[columnIndex].textContent;
                if (isNumeric) {
                    valA = parseFloat(valA) || 0;
                    valB = parseFloat(valB) || 0;
                }

                if (currentSortDirection === "asc") {
                    return valA > valB ? 1 : valA < valB ? -1 : 0;
                } else {
                    return valA < valB ? 1 : valA > valB ? -1 : 0;
                }
            });

            rows.forEach(row => tbody.insertBefore(row, totalsRow));
            updateRowNumbers();
        }

        function updateSortIndicators() {
            const ths = document.querySelectorAll("#summaryTable th");
            ths.forEach((th, index) => {
                th.classList.remove("sorted-asc", "sorted-desc");
                if (index === currentSortColumn) {
                    th.classList.add(currentSortDirection === "asc" ? "sorted-asc" : "sorted-desc");
                }
            });
        }

        function updateRowNumbers() {
            const table = document.getElementById("summaryTable");
            const rows = Array.from(table.querySelectorAll("tbody tr")).filter(row => !row.classList.contains('totals-row'));
            rows.forEach((row, index) => {
                row.querySelector("td").textContent = index + 1;
            });
        }

        function filterTable() {
            const filterInputs = document.querySelectorAll('.filter-container input');
            const table = document.getElementById("summaryTable");
            const rows = Array.from(table.querySelectorAll("tbody tr")).filter(row => !row.classList.contains('totals-row'));

            rows.forEach(row => {
                const cells = Array.from(row.getElementsByTagName("TD")).slice(1);
                let showRow = true;
                filterInputs.forEach((input, index) => {
                    const filterValue = input.value.toLowerCase();
                    if (filterValue && !cells[index].innerText.toLowerCase().includes(filterValue)) {
                        showRow = false;
                    }
                });
                row.style.display = showRow ? "" : "none";
            });
            updateRowNumbers();
        }
    </script>
</head>
<body>
    <h1>Keys Management</h1>
    <div class="filter-container">
        <input type="text" placeholder="Фильтр по Email">
        <input type="text" placeholder="Фильтр по Ключу">
        <input type="text" placeholder="Фильтр по Названиям ключей">
        <input type="text" placeholder="Фильтр по Датам начала">
        <input type="text" placeholder="Фильтр по Датам окончания">
        <input type="text" placeholder="Фильтр по Статусам">
        <input type="text" placeholder="Фильтр по Тарифам">
    </div>
    <div class="container">
        <form method="POST" id="dateForm" class="date-form">
            <label for="start_date">Дата начала:</label>
            <input type="text" id="start_date" name="start_date" value="{{ start_date }}" class="form-control">
            <button type="submit" class="btn btn-primary">Показать</button>
        </form>
        <div class="show-all">
            <a href="?page=1&per_page=-1&start_date={{ start_date }}" class="btn btn-secondary">Показать все записи</a>
        </div>
        <table id="summaryTable" class="table table-striped keys-table">
            <thead>
                <tr>
                    <th onclick="sortTable(0, true)">#</th>
                    <th onclick="sortTable(1)" class="email-column">Email</th>
                    <th onclick="sortTable(2)">Ключи</th>
                    <th onclick="sortTable(3)" class="key-name-column">Названия ключей</th>
                    <th onclick="sortTable(4)" class="date-column">Даты начала</th>
                    <th onclick="sortTable(5)" class="date-column">Даты окончания</th>
                    <th onclick="sortTable(6)" class="status-column">Статусы</th>
                    <th onclick="sortTable(7)" class="tariff-column">Тарифы</th>
                    <th class="login-column">Вход</th>
                </tr>
            </thead>
            <tbody>
                {% set i = 1 %}
                {% for email, keys in paginated_user_keys_dict.items() %}
                <tr>
                    <td>{{ i }}</td>
                    <td class="email-column">{{ email }}</td>
                    <td>
                        {% for key in keys %}
                            <div class="key-entry">{{ key['key'] }}</div>
                        {% endfor %}
                    </td>
                    <td class="key-name-column">
                        {% for key in keys %}
                            <div class="key-entry">{{ key['key_name'] }}</div>
                        {% endfor %}
                    </td>
                    <td class="date-column">
                        {% for key in keys %}
                            <div class="key-entry">{{ key['start_date'] }}</div>
                        {% endfor %}
                    </td>
                    <td class="date-column">
                        {% for key in keys %}
                            <div class="key-entry">{{ key['end_date'] }}</div>
                        {% endfor %}
                    </td>
                    <td class="status-column">
                        {% for key in keys %}
                            <div class="key-entry">{{ key['status'] }}</div>
                        {% endfor %}
                    </td>
                    <td class="tariff-column">
                        {% for key in keys %}
                            <div class="key-entry">{{ key['name'] }}</div>
                        {% endfor %}
                    </td>
                    <td class="login-column">
                        <form action="{{ url_for('client_details', email=email) }}" method="get">
                            <button type="submit" class="login-btn">Вход</button>
                        </form>
                    </td>
                </tr>
                {% set i = i + 1 %}
                {% endfor %}
            </tbody>
        </table>
        <div class="pagination">
            {% if page > 1 %}
            <a href="?page={{ page - 1 }}&per_page={{ per_page }}&start_date={{ start_date }}">&laquo; Предыдущая</a>
            {% endif %}
            {% for p in range(1, (total // per_page) + 2) %}
            <a href="?page={{ p }}&per_page={{ per_page }}&start_date={{ start_date }}" class="{% if p == page %}active{% endif %}">{{ p }}</a>
            {% endfor %}
            {% if page * per_page < total %}
            <a href="?page={{ page + 1 }}&per_page={{ per_page }}&start_date={{ start_date }}">Следующая &raquo;</a>
            {% endif %}
        </div>
    </div>
</body>
</html>

'''

    return render_template_string(template, paginated_user_keys_dict=paginated_user_keys_dict, start_date=start_date, page=page, per_page=per_page, total=total)
    
    
@app.route('/client/<email>', methods=['GET'])
@login_required
@role_required('admin')
def client_details(email):
    role = current_user.role
    users, user_tariffs, tariffs, user_keys, miner_data = get_data_for_user(role)

    # Получение данных о платежах
    payments = Payment.query.all()
    payments_df = pd.DataFrame([{
        'user_id': p.user_id,
        'amount': p.amount,
        'extension_days': p.extension_days,
        'payment_date': p.payment_date,
        'key': p.key,
        'payment_id': p.payment_id,
        'processed': p.processed
    } for p in payments])

    # Получение данных о партнёрах
    partners = PartnerManagerAssociation.query.all()
    managers = ManagerSupervisorAssociation.query.all()
    partner_manager_df = pd.DataFrame([{
        'partner_id': p.partner_id,
        'manager_id': p.manager_id
    } for p in partners])
    manager_supervisor_df = pd.DataFrame([{
        'manager_id': m.manager_id,
        'supervisor_id': m.supervisor_id
    } for m in managers])

    # Объединение данных ключей с тарифами
    user_keys_with_tariffs = user_keys.merge(tariffs, left_on='tariff_id', right_on='tariff_id', how='left', suffixes=('', '_tariffs'))

    # Объединение данных пользователей с ключами
    merged_data = users.merge(user_keys_with_tariffs, left_on='id', right_on='user_id', how='left', suffixes=('', '_user_keys'))

    # Добавление данных о майнерах (Асики)
    if 'hs_rt' in miner_data.columns:
        miner_data['device_info'] = miner_data.apply(lambda row: {
            'device_model': row['device_model'],
            'mhs_av': row['mhs_av'],
            'hs_rt': row['hs_rt'],
            'temperature': row['temperature'],
            'fan_speed_in': row['fan_speed_in'],
            'fan_speed_out': row['fan_speed_out'],
            'power': row['power'],
            'uptime_hours': row['uptime_hours'],
            'uptime_minutes': row['uptime_minutes'],
            'power_mode': row['power_mode'],
            'power_limit': row['power_limit'],
            'pool_url': row['pool_url'],
            'pool_user': row['pool_user'],
            'status': 'Активный' if row['status'] == 1 else 'Отключенный'
        }, axis=1)
        miner_details = miner_data.groupby(['user_id', 'key'])['device_info'].apply(list).reset_index(name='device_models')
        merged_data = merged_data.merge(miner_details, on=['user_id', 'key'], how='left')
        merged_data['asic_count'] = merged_data['device_models'].apply(lambda x: len(x) if isinstance(x, list) else 0)
    else:
        merged_data['device_models'] = None
        merged_data['asic_count'] = 0

    # Подключение к базе данных /root/websocket/devices_data.db для проверки статуса ключа
    def get_device_status(key):
        conn = sqlite3.connect('/root/websocket/devices_data.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM device_data WHERE uid = ?", (key,))
        device_data = cursor.fetchone()
        conn.close()
        return 'Online' if device_data else 'Offline'

    # Добавление статуса Online/Offline для каждого ключа
    merged_data['online_status'] = merged_data['key'].apply(get_device_status)

    # Проверка наличия столбца 'payment_status' и заполнение NaN значений
    if 'payment_status' not in merged_data.columns:
        merged_data['payment_status'] = 'Не оплачено'

    # Выбор данных конкретного пользователя по email
    client_data = merged_data[merged_data['email'] == email]
    if client_data.empty:
        return "User not found", 404
    user_info = users[users['email'] == email].iloc[0]

    # Данные по платежам конкретного пользователя
    client_payments = payments_df[payments_df['user_id'] == user_info['id']]

    # Подключение к базе данных instance/users.db для извлечения данных о партнёрах и ключах
    partner_db_engine = create_engine('sqlite:///' + os.path.join(BASE_DIR, 'instance/users.db'))
    partner_connection = partner_db_engine.connect()

    # Извлечение данных о ключах и партнёрах из базы данных instance/users.db
    partner_keys_query = '''
        SELECT uk.key, u.username AS partner_name
        FROM user_key AS uk
        JOIN user AS u ON uk.user_id = u.id
    '''
    partner_keys_df = pd.read_sql(partner_keys_query, partner_connection)

    # Закрытие соединения с базой данных
    partner_connection.close()

    # Отфильтровать ключи, которые принадлежат пользователю
    user_keys_set = set(client_data['key'])
    partner_keys_df = partner_keys_df[partner_keys_df['key'].isin(user_keys_set)]

    template = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Client Details</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            padding: 20px;
            background-color: #f7f7f7;
            font-family: Arial, sans-serif;
        }
        .container {
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1, h2 {
            text-align: center;
            margin-bottom: 20px;
        }
        .client-info, .client-keys, .client-payments, .client-partners {
            margin-bottom: 20px;
        }
        .client-info th, .client-info td, .client-keys th, .client-keys td, .client-payments th, .client-payments td, .client-partners th, .client-partners td {
            padding: 10px;
            text-align: left;
        }
        .client-info th, .client-keys th, .client-payments th, .client-partners th {
            width: 12.5%;
        }
        .back-btn {
            display: block;
            width: 100px;
            margin: 0 auto 20px;
            padding: 10px;
            background-color: #007bff;
            color: white;
            text-align: center;
            border-radius: 4px;
            text-decoration: none;
        }
        .back-btn:hover {
            background-color: #0056b3;
        }
        .status-circle {
            height: 15px;
            width: 15px;
            border-radius: 50%;
            display: inline-block;
        }
        .status-online {
            background-color: green;
        }
        .status-offline {
            background-color: black;
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 1;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgb(0,0,0);
            background-color: rgba(0,0,0,0.4);
            padding-top: 60px;
        }
        .modal-content {
            background-color: #fefefe;
            margin: 5% auto;
            padding: 20px;
            border: 1px solid #888;
            width: 80%;
        }
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
        }
        .close:hover,
        .close:focus {
            color: black;
            text-decoration: none;
            cursor: pointer;
        }
        .device-list {
            max-height: 200px;
            overflow-y: auto;
            list-style-type: none;
            padding-left: 0;
        }
        .device-list li {
            display: inline-block;
            padding: 5px;
        }
    </style>
</head>
<body>
    <a href="{{ url_for('keys_management_view') }}" class="back-btn">Назад</a>
    <div class="container">
        <h1>Информация о клиенте</h1>
        <h2>{{ email }}</h2>
        <table class="client-info table table-bordered">
            <tr>
                <th>Телефон</th>
                <td>{{ phone_number }}</td>
            </tr>
            <tr>
                <th>Почта</th>
                <td>{{ email }}</td>
            </tr>
            <tr>
                <th>Пароль</th>
                <td>{{ user_info['password'] }}</td>
            </tr>
        </table>
        <h2>Ключи</h2>
        <table class="client-keys table table-bordered">
            <thead>
                <tr>
                    <th>Ключ</th>
                    <th>Название ключа</th>
                    <th class="date-column">Дата начала</th>
                    <th class="date-column">Дата окончания</th>
                    <th>Статус</th>
                    <th>Тариф</th>
                    <th>Асики</th>
                    <th>Статус устройства</th>
                    <th>Вход по ключу</th>
                    <th>Действие</th>
                </tr>
            </thead>
            <tbody>
                {% for index, row in client_data.iterrows() %}
                <tr>
                    <td>{{ row['key'] }}</td>
                    <td>{{ row['key_name'] }}</td>
                    <td>{{ row['start_date'] }}</td>
                    <td>{{ row['end_date'] }}</td>
                    <td>{{ row['status'] }}</td>
                    <td>{{ row['name'] }}</td>
                    <td>
                        <a href="javascript:void(0);" onclick="showAsicsModal({{ loop.index }})">{{ row['asic_count'] }}</a>
                        <div id="modal-{{ loop.index }}" class="modal">
                            <div class="modal-content">
                                <span class="close" onclick="closeAsicsModal({{ loop.index }})">&times;</span>
                                <h3>Устройства</h3>
                                <ul class="device-list">
                                    {% if row['device_models'] and row['device_models'] is iterable %}
                                        {% for device in row['device_models'] %}
                                        <li>
                                            <div class="device-info">
                                                {{ device.device_model }} | {{ device.mhs_av }} | {{ device.hs_rt }} | {{ device.temperature }} | {{ device.fan_speed_in }} | {{ device.fan_speed_out }} | {{ device.power }} | {{ device.uptime_hours }} | {{ device.uptime_minutes }} | {{ device.power_mode }} | {{ device.power_limit }} | {{ device.pool_url }} | {{ device.pool_user }} | {{ device.status }}
                                            </div>
                                        </li>
                                        {% endfor %}
                                    {% else %}
                                        <li>Нет доступных устройств</li>
                                    {% endif %}
                                </ul>
                            </div>
                        </div>
                    </td>
                    <td>
                        {% if row['online_status'] == 'Online' %}
                            <span class="status-circle status-online"></span> Online
                        {% else %}
                            <span class="status-circle status-offline"></span> Offline
                        {% endif %}
                    </td>
                    <td><a href="/key_access/{{ row['key'] }}" class="btn btn-primary">Вход</a></td>
                    <td><a href="#">Выставить счёт</a></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        <h2>Платежи</h2>
        <table class="client-payments table table-bordered">
            <thead>
                <tr>
                    <th>Дата платежа</th>
                    <th>Сумма</th>
                    <th>Дни продления</th>
                    <th>Ключ</th>
                    <th>Идентификатор платежа</th>
                    <th>Обработан</th>
                </tr>
            </thead>
            <tbody>
                {% for index, row in client_payments.iterrows() %}
                <tr>
                    <td>{{ row['payment_date'] }}</td>
                    <td>{{ row['amount'] }}</td>
                    <td>{{ row['extension_days'] }}</td>
                    <td>{{ row['key'] }}</td>
                    <td>{{ row['payment_id'] }}</td>
                    <td>{{ 'Да' if row['processed'] else 'Нет' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        <h2>Ключи и Партнёры</h2>
        <table class="client-partners table table-bordered">
            <thead>
                <tr>
                    <th>Ключ</th>
                    <th>Партнёр</th>
                </tr>
            </thead>
            <tbody>
                {% for index, row in partner_keys_df.iterrows() %}
                <tr>
                    <td>{{ row['key'] }}</td>
                    <td>{{ row['partner_name'] }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    <script>
        function showAsicsModal(index) {
            document.getElementById('modal-' + index).style.display = "block";
        }
        function closeAsicsModal(index) {
            document.getElementById('modal-' + index).style.display = "none";
        }
    </script>
</body>
</html>
    '''

    return render_template_string(template, client_data=client_data, email=email, user_info=user_info, client_payments=client_payments, partner_keys_df=partner_keys_df)




# Обработка данных и отображение сводной таблицы
@app.route('/data')
@login_required
@role_required('admin')
def data_view():
    role = current_user.role
    users, user_tariffs, tariffs, user_keys, miner_data = get_data_for_user(role)

    # Подсчет количества ключей и их список для каждого пользователя
    user_keys_count = user_keys.groupby('user_id').size().reset_index(name='key_count')
    user_keys_list = user_keys.groupby('user_id')['key'].apply(lambda x: ', '.join(x)).reset_index(name='keys')

    # Подсчет количества устройств для каждого пользователя и общего хэшрейта
    miner_devices_count = miner_data.groupby('user_id').size().reset_index(name='devices_count')

    # Подсчет хэшрейта LTC и BTC
    miner_hashrate_ltc = miner_data[miner_data['device_model'].str.contains('Antminer L7', na=False)].groupby('user_id')['mhs_av'].sum().reset_index(name='ltc_hashrate')
    miner_hashrate_btc = miner_data[~miner_data['device_model'].str.contains('Antminer L7', na=False)].groupby('user_id')['mhs_av'].sum().reset_index(name='btc_hashrate')

    # Объединение данных
    merged_data = users.merge(user_tariffs, left_on='id', right_on='user_id', how='left', suffixes=('', '_user_tariffs'))
    merged_data = merged_data.merge(tariffs, on='tariff_id', how='left', suffixes=('', '_tariffs'))
    merged_data = merged_data.merge(user_keys_count, left_on='id', right_on='user_id', how='left', suffixes=('', '_user_keys'))
    merged_data = merged_data.merge(user_keys_list, left_on='id', right_on='user_id', how='left', suffixes=('', '_user_keys_list'))
    merged_data = merged_data.merge(miner_devices_count, left_on='id', right_on='user_id', how='left', suffixes=('', '_miner_data'))
    merged_data = merged_data.merge(miner_hashrate_ltc, left_on='id', right_on='user_id', how='left', suffixes=('', '_miner_data'))
    merged_data = merged_data.merge(miner_hashrate_btc, left_on='id', right_on='user_id', how='left', suffixes=('', '_miner_data'))

    # Заполнение NaN значений
    merged_data['name'].fillna('Без тарифа', inplace=True)
    merged_data['start_date'].fillna('N/A', inplace=True)
    merged_data['end_date'].fillna('N/A', inplace=True)
    merged_data['devices_count'].fillna(0, inplace=True)
    merged_data['ltc_hashrate'].fillna(0, inplace=True)
    merged_data['btc_hashrate'].fillna(0, inplace=True)
    merged_data['key_count'].fillna(0, inplace=True)
    merged_data['keys'].fillna('Нет устройств', inplace=True)

    # Определение столбцов для сводной таблицы
    summary_table = merged_data[['id', 'email', 'name', 'start_date', 'end_date', 'devices_count', 'ltc_hashrate', 'btc_hashrate', 'key_count', 'keys']]
    summary_table.columns = ['ID', 'Email', 'Тариф', 'Дата начала', 'Дата окончания', 'Количество устройств', 'Хэшрейт LTC', 'Хэшрейт BTC', 'Количество ключей', 'Ключи']

    # Вычисление итогов
    total_devices = summary_table['Количество устройств'].sum()
    total_ltc_hashrate = summary_table['Хэшрейт LTC'].sum()
    total_btc_hashrate = summary_table['Хэшрейт BTC'].sum()
    total_keys = summary_table['Количество ключей'].sum()

    # Шаблон для отображения таблицы
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Сводная таблица</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
            }
            h1 {
                text-align: center;
            }
            .filter-container {
                margin-bottom: 20px;
                text-align: center;
            }
            .filter-container input {
                margin: 5px;
                padding: 10px;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            table {
                border-collapse: collapse;
                width: 100%;
                margin-bottom: 20px;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
                cursor: pointer;
                position: relative;
            }
            th.sorted-asc::after, th.sorted-desc::after {
                content: "";
                position: absolute;
                right: 8px;
            }
            th.sorted-asc::after {
                content: "▲";
            }
            th.sorted-desc::after {
                content: "▼";
            }
            tr:hover {
                background-color: #f5f5f5;
            }
            .tooltip {
                position: relative;
                display: inline-block;
            }
            .tooltip .tooltiptext {
                visibility: hidden;
                width: 300px;
                background-color: black;
                color: #fff;
                text-align: left;
                border-radius: 5px;
                padding: 5px;
                position: absolute;
                z-index: 1;
                bottom: 100%;
                left: 50%;
                margin-left: -150px;
                opacity: 0;
                transition: opacity 0.3s;
                max-height: 400px;
                overflow-y: auto;
            }
            .tooltip:hover .tooltiptext {
                visibility: visible;
                opacity: 1;
            }
            #deviceModal {
                display: none;
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background-color: white;
                padding: 20px;
                border: 1px solid black;
                z-index: 1000;
                max-height: 80%;
                overflow-y: auto;
            }
            .close-modal {
                background-color: #f44336;
                color: white;
                padding: 10px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }
            .totals-row {
                font-weight: bold;
                background-color: #f9f9f9;
            }
            .back-button {
                display: block;
                margin-bottom: 20px;
                padding: 10px 20px;
                background-color: #4CAF50;
                color: white;
                text-decoration: none;
                border-radius: 4px;
                text-align: center;
                width: 100px;
            }
        </style>
        <script>
            let currentSortColumn = -1;
            let currentSortDirection = "asc";

            function sortTable(columnIndex, isNumeric=false) {
                const table = document.getElementById("summaryTable");
                const tbody = table.querySelector("tbody");
                let rows = Array.from(tbody.querySelectorAll("tr:not(.totals-row)"));
                const totalsRow = tbody.querySelector(".totals-row");

                if (columnIndex === currentSortColumn) {
                    currentSortDirection = currentSortDirection === "asc" ? "desc" : "asc";
                } else {
                    currentSortColumn = columnIndex;
                    currentSortDirection = "asc";
                }
                updateSortIndicators();

                rows.sort((a, b) => {
                    let valA = a.children[columnIndex].textContent;
                    let valB = b.children[columnIndex].textContent;
                    if (isNumeric) {
                        valA = parseFloat(valA) || 0;
                        valB = parseFloat(valB) || 0;
                    }

                    if (currentSortDirection === "asc") {
                        return valA > valB ? 1 : valA < valB ? -1 : 0;
                    } else {
                        return valA < valB ? 1 : valA > valB ? -1 : 0;
                    }
                });

                rows.forEach(row => tbody.insertBefore(row, totalsRow));
            }

            function updateSortIndicators() {
                const ths = document.querySelectorAll("#summaryTable th");
                ths.forEach((th, index) => {
                    th.classList.remove("sorted-asc", "sorted-desc");
                    if (index === currentSortColumn) {
                        th.classList.add(currentSortDirection === "asc" ? "sorted-asc" : "sorted-desc");
                    }
                });
            }

            function showDevices(userId) {
                fetch('/devices/' + userId)
                    .then(response => response.json())
                    .then(data => {
                        let deviceList = '<ul>';
                        data.devices.forEach(device => {
                            deviceList += `<li>${device}</li>`;
                        });
                        deviceList += '</ul>';
                        const modal = document.getElementById('deviceModal');
                        modal.innerHTML = `<h2>Устройства пользователя ${userId}</h2>${deviceList}<button class="close-modal" onclick="closeModal()">Закрыть</button>`;
                        modal.style.display = 'block';
                    })
                    .catch(error => console.error('Error fetching devices:', error));
            }

            function closeModal() {
                const modal = document.getElementById('deviceModal');
                modal.style.display = 'none';
            }

            function filterTable() {
                const filterInputs = document.querySelectorAll('.filter-container input');
                const filterValues = Array.from(filterInputs).map(input => input.value.toLowerCase());
                const table = document.getElementById("summaryTable");
                const rows = Array.from(table.querySelectorAll("tbody tr")).filter(row => !row.classList.contains('totals-row'));

                rows.forEach(row => {
                    const cells = Array.from(row.getElementsByTagName("TD"));
                    const match = cells.every((cell, index) => cell.innerText.toLowerCase().includes(filterValues[index]));
                    row.style.display = match ? "" : "none";
                });
            }

            document.addEventListener("DOMContentLoaded", () => {
                const filterInputs = document.querySelectorAll('.filter-container input');
                filterInputs.forEach(input => input.addEventListener('keyup', filterTable));
            });
        </script>
    </head>
    <body>
        <a href="javascript:history.back()" class="back-button">Назад</a>
        <h1>Сводная таблица</h1>
        <div class="filter-container">
            <input type="text" placeholder="Фильтр по ID">
            <input type="text" placeholder="Фильтр по Email">
            <input type="text" placeholder="Фильтр по Тарифу">
            <input type="text" placeholder="Фильтр по Дата начала">
            <input type="text" placeholder="Фильтр по Дата окончания">
            <input type="text" placeholder="Фильтр по Количество устройств">
            <input type="text" placeholder="Фильтр по Хэшрейт LTC">
            <input type="text" placeholder="Фильтр по Хэшрейт BTC">
            <input type="text" placeholder="Фильтр по Количество ключей">
            <input type="text" placeholder="Фильтр по Ключи">
        </div>
        <table id="summaryTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0, true)">ID</th>
                    <th onclick="sortTable(1)">Email</th>
                    <th onclick="sortTable(2)">Тариф</th>
                    <th onclick="sortTable(3)">Дата начала</th>
                    <th onclick="sortTable(4)">Дата окончания</th>
                    <th onclick="sortTable(5, true)">Количество устройств</th>
                    <th onclick="sortTable(6, true)">Хэшрейт LTC</th>
                    <th onclick="sortTable(7, true)">Хэшрейт BTC</th>
                    <th onclick="sortTable(8, true)">Количество ключей</th>
                    <th onclick="sortTable(9)">Ключи</th>
                </tr>
            </thead>
            <tbody>
                {% for row in rows %}
                <tr>
                    {% for i, item in enumerate(row) %}
                        <td>{% if i == 5 %}
                            <a href="javascript:void(0)" onclick="showDevices({{ row[0] }})">{{ item }}</a>
                        {% elif i == 9 %}
                            <div class="tooltip">{{ item.split(',')[0] }}{% if item.split(',')|length > 1 %}...{% endif %}
                                <span class="tooltiptext">{{ item }}</span>
                            </div>
                        {% else %}
                            {{ item }}
                        {% endif %}</td>
                    {% endfor %}
                </tr>
                {% endfor %}
                <tr class="totals-row">
                    <td colspan="5">Итого</td>
                    <td>{{ total_devices }}</td>
                    <td>{{ total_ltc_hashrate }}</td>
                    <td>{{ total_btc_hashrate }}</td>
                    <td>{{ total_keys }}</td>
                    <td></td>
                </tr>
            </tbody>
        </table>
        <div id="deviceModal"></div>
    </body>
    </html>
    '''

    return render_template_string(template, columns=summary_table.columns, rows=summary_table.values.tolist(), enumerate=enumerate,
                                  total_devices=total_devices, total_ltc_hashrate=total_ltc_hashrate, total_btc_hashrate=total_btc_hashrate,
                                  total_keys=total_keys)


@app.route('/devices/<int:user_id>')
def devices_view(user_id):
    conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT key, miner_ip, device_model FROM miner_data WHERE user_id = ?", (user_id,))
    devices = cursor.fetchall()
    conn.close()

    devices_list = [f"Key: {key}, IP: {miner_ip}, Model: {device_model}" for key, miner_ip, device_model in devices]
    return jsonify(devices=devices_list)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = secrets.token_urlsafe(16)
            user.reset_token = token
            db.session.commit()
            reset_link = url_for('reset_password_token', token=token, _external=True)
            subject = 'Сброс пароля'
            message = f'Для сброса пароля перейдите по ссылке: {reset_link}'
            send_email(email, subject, message)
            flash('Ссылка для сброса пароля отправлена на ваш email')
        else:
            flash('Пользователь с таким email не найден')

        return redirect(url_for('login'))

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Сброс пароля</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .form-container {
                max-width: 500px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .form-container h1 {
                text-align: center;
                margin-bottom: 20px.
            }
            .form-group {
                margin-bottom: 15px.
            }
            .btn-primary {
                display: block;
                width: 100%.
            }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h1>Сброс пароля</h1>
            <form method="POST">
                <div class="form-group">
                    <input type="email" name="email" class="form-control" placeholder="Email" required>
                </div>
                <button type="submit" class="btn btn-primary">Сбросить пароль</button>
            </form>
        </div>
    </body>
    </html>
    ''')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash('Ссылка для сброса пароля недействительна')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form['password']
        user.password = generate_password_hash(password, method='sha256')
        user.reset_token = None
        db.session.commit()
        flash('Пароль успешно обновлен')
        return redirect(url_for('login'))

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Сброс пароля</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .form-container {
                max-width: 500px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9.
            }
            .form-container h1 {
                text-align: center;
                margin-bottom: 20px.
            }
            .form-group {
                margin-bottom: 15px.
            }
            .btn-primary {
                display: block;
                width: 100%.
            }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h1>Сброс пароля</h1>
            <form method="POST">
                <div class="form-group">
                    <input type="password" name="password" class="form-control" placeholder="Новый пароль" required>
                </div>
                <button type="submit" class="btn btn-primary">Обновить пароль</button>
            </form>
        </div>
    </body>
    </html>
    ''')


def setup_database(conn):
    """ Создает таблицу в базе данных, если она еще не создана. """
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS daily_metrics (
        date TEXT PRIMARY KEY,
        total_ltc_hashrate REAL,
        total_btc_hashrate REAL,
        total_ltc_devices INTEGER,
        total_btc_devices INTEGER,
        total_keys INTEGER,
        keys_new INTEGER,
        keys_active INTEGER,
        keys_inactive INTEGER
    )
    ''')
    conn.commit()


def periodic_save(read_db_path, write_db_path, interval):
    while True:
        try:
            with sqlite3.connect(read_db_path) as read_conn, sqlite3.connect(write_db_path) as write_conn:
                setup_database(write_conn)

                current_date = datetime.now().date()
                read_cursor = read_conn.cursor()
                write_cursor = write_conn.cursor()

                # Чтение данных о майнерах
                read_cursor.execute("SELECT key, mhs_av, device_model FROM miner_data")
                miner_data = pd.DataFrame(read_cursor.fetchall(), columns=['key', 'mhs_av', 'device_model'])

                # Расчет хэшрейтов и количества устройств
                miner_hashrate_ltc = round(miner_data[miner_data['device_model'].str.contains('Antminer L7', na=False)]['mhs_av'].sum(), 2)
                miner_hashrate_btc = round(miner_data[~miner_data['device_model'].str.contains('Antminer L7', na=False)]['mhs_av'].sum(), 2)
                miner_devices_ltc = miner_data[miner_data['device_model'].str.contains('Antminer L7', na=False)].shape[0]
                miner_devices_btc = miner_data[~miner_data['device_model'].str.contains('Antminer L7', na=False)].shape[0]

                # Чтение данных о ключах
                total_keys = read_cursor.execute("SELECT COUNT(*) FROM user_keys").fetchone()[0]
                keys_new = read_cursor.execute("SELECT COUNT(*) FROM user_keys WHERE status='new'").fetchone()[0]
                keys_active = read_cursor.execute("SELECT COUNT(*) FROM user_keys WHERE status='active'").fetchone()[0]
                keys_inactive = read_cursor.execute("SELECT COUNT(*) FROM user_keys WHERE status='inactive'").fetchone()[0]

                # Сохранение агрегированных данных
                metrics = {
                    'date': str(current_date),
                    'total_ltc_hashrate': miner_hashrate_ltc,
                    'total_btc_hashrate': miner_hashrate_btc,
                    'total_ltc_devices': miner_devices_ltc,
                    'total_btc_devices': miner_devices_btc,
                    'total_keys': total_keys,
                    'keys_new': keys_new,
                    'keys_active': keys_active,
                    'keys_inactive': keys_inactive
                }
                write_cursor.execute('''
                INSERT OR REPLACE INTO daily_metrics (date, total_ltc_hashrate, total_btc_hashrate, total_ltc_devices, total_btc_devices, total_keys, keys_new, keys_active, keys_inactive)
                VALUES (:date, :total_ltc_hashrate, :total_btc_hashrate, :total_ltc_devices, :total_btc_devices, :total_keys, :keys_new, :keys_active, :keys_inactive)
                ''', metrics)
                write_conn.commit()

        except Exception as e:
            print(f"Ошибка при выполнении: {e}")

        time.sleep(interval)



def get_db_connection():
    conn = sqlite3.connect('/root/cabinet/instance/metrics.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/daily_metrics')
def daily_metrics():
    conn = get_db_connection()
    try:
        today = datetime.now().date()
        yesterday = today - timedelta(days=1)

        query = '''
        SELECT date, total_ltc_hashrate, total_btc_hashrate, total_ltc_devices, total_btc_devices, total_keys,
               keys_new, keys_active, keys_inactive
        FROM daily_metrics
        WHERE date IN (?, ?)
        '''
        df = pd.read_sql_query(query, conn, params=[str(yesterday), str(today)])
        df['date'] = pd.to_datetime(df['date']).dt.date

        today_data = df[df['date'] == today]
        yesterday_data = df[df['date'] == yesterday]

        def safe_sum(series):
            return series.sum().item() if not series.empty else 0

        metrics = {
            'labels': ['Хэшрейт LTC', 'Хэшрейт BTC', 'Асики LTC', 'Асики BTC', 'Всего ключей', 'Новые ключи', 'Активные ключи', 'Неактивные ключи'],
            'today': [safe_sum(today_data[col]) for col in df.columns[1:]],
            'yesterday': [safe_sum(yesterday_data[col]) for col in df.columns[1:]],
            'growth': [
                round(((safe_sum(today_data[col]) - safe_sum(yesterday_data[col])) / safe_sum(yesterday_data[col]) * 100 if safe_sum(yesterday_data[col]) > 0 else 0), 2)
                for col in df.columns[1:]
            ]
        }
    finally:
        conn.close()

    return render_template_string(template, metrics=metrics) # Или jsonify(metrics) для API-ответа




template = '''

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="60">
    <title>Ежедневные метрики</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            text-align: center;
            background-color: #f2f9ff;
            color: #03396c;
        }
        header {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
        }
        header img {
            width: 50px;
            height: 50px;
            margin-right: 10px;
        }
        header h1 {
            margin: 0;
            font-size: 1.5em;
        }
        .main-title {
            margin-bottom: 30px;
        }
        h2 {
            margin: 20px 0;
            color: #004d99;
        }
        table {
            width: 100%;
            max-width: 1000px;
            margin: 20px auto;
            border-collapse: collapse;
        }
        th, td {
            border: 1px solid #03396c;
            padding: 8px;
            text-align: center;
        }
        th {
            background-color: #b3d4fc;
        }
        td {
            background-color: #e6f2ff;
        }
    </style>
</head>
<body>
    <header>
        <img src="{{ url_for('static', filename='512x512_logo.jpeg') }}" alt="Лого">
        <h1>Сова Мониторинг</h1>
    </header>
    <h1 class="main-title">Ежедневные метрики</h1>
    <table>
        <thead>
            <tr>
                <th>Метрика</th>
                <th>Сегодня</th>
                <th>Вчера</th>
                <th>Рост (%)</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <th colspan="4">Хэшрейт</th>
            </tr>
            <tr>
                <td>Хэшрейт LTC</td>
                <td>{{ metrics.today[0] }}</td>
                <td>{{ metrics.yesterday[0] }}</td>
                <td>{{ metrics.growth[0] }}%</td>
            </tr>
            <tr>
                <td>Хэшрейт BTC</td>
                <td>{{ metrics.today[1] }}</td>
                <td>{{ metrics.yesterday[1] }}</td>
                <td>{{ metrics.growth[1] }}%</td>
            </tr>
            <tr>
                <th colspan="4">Асики</th>
            </tr>
            <tr>
                <td>Асики LTC</td>
                <td>{{ metrics.today[2] }}</td>
                <td>{{ metrics.yesterday[2] }}</td>
                <td>{{ metrics.growth[2] }}%</td>
            </tr>
            <tr>
                <td>Асики BTC</td>
                <td>{{ metrics.today[3] }}</td>
                <td>{{ metrics.yesterday[3] }}</td>
                <td>{{ metrics.growth[3] }}%</td>
            </tr>
            <tr>
                <th colspan="4">Мониторы</th>
            </tr>
            <tr>
                <td>Всего мониторов</td>
                <td>{{ metrics.today[4] }}</td>
                <td>{{ metrics.yesterday[4] }}</td>
                <td>{{ metrics.growth[4] }}%</td>
            </tr>
            <tr>
                <td>Новые мониторы</td>
                <td>{{ metrics.today[5] }}</td>
                <td>{{ metrics.yesterday[5] }}</td>
                <td>{{ metrics.growth[5] }}%</td>
            </tr>
            <tr>
                <td>Активные мониторы</td>
                <td>{{ metrics.today[6] }}</td>
                <td>{{ metrics.yesterday[6] }}</td>
                <td>{{ metrics.growth[6] }}%</td>
            </tr>
            <tr>
                <td>Неактивные мониторы</td>
                <td>{{ metrics.today[7] }}</td>
                <td>{{ metrics.yesterday[7] }}</td>
                <td>{{ metrics.growth[7] }}%</td>
            </tr>
        </tbody>
    </table>
    <h2>Метрики по партнёрам</h2>
</body>
</html>

'''

# Определение пути к файлу базы данных
db_path = "/root/cabinet/instance/metrics.db"

# Запуск функции periodic_save в отдельном потоке
thread = threading.Thread(target=periodic_save, args=(SECONDARY_DATABASE_PATH, db_path, 86400))  # Сохранение раз в сутки (86400 секунд)
thread.daemon = True
thread.start()

# Маршруты для управления тарифами
@app.route('/create_tariff', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_tariff():
    if request.method == 'POST':
        name = request.form['name']
        base_price = float(request.form['base_price'])
        partner_initial_payment = float(request.form['partner_initial_payment'])
        manager_initial_payment = float(request.form['manager_initial_payment'])
        supervisor_initial_payment = float(request.form['supervisor_initial_payment'])
        partner_subscription_percentage = float(request.form['partner_subscription_percentage'])
        manager_subscription_percentage = float(request.form['manager_subscription_percentage'])
        supervisor_subscription_percentage = float(request.form['supervisor_subscription_percentage'])
        restricted = 'restricted' in request.form

        new_tariff = Tariff(
            name=name,
            base_price=base_price,
            partner_initial_payment=partner_initial_payment,
            manager_initial_payment=manager_initial_payment,
            supervisor_initial_payment=supervisor_initial_payment,
            partner_subscription_percentage=partner_subscription_percentage,
            manager_subscription_percentage=manager_subscription_percentage,
            supervisor_subscription_percentage=supervisor_subscription_percentage,
            restricted=restricted
        )
        db.session.add(new_tariff)
        db.session.commit()
        flash('Тариф успешно создан')
        return redirect(url_for('list_tariffs'))

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Создать тариф</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .form-container {
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .form-container h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .form-group {
                margin-bottom: 15px;
            }
            .btn-primary {
                display: block;
                width: 100%;
            }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h1>Создать тариф</h1>
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="name" class="form-control" placeholder="Название тарифа" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="base_price" class="form-control" placeholder="Базовая цена" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="partner_initial_payment" class="form-control" placeholder="Первоначальный платеж партнера" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="manager_initial_payment" class="form-control" placeholder="Первоначальный платеж менеджера" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="supervisor_initial_payment" class="form-control" placeholder="Первоначальный платеж супервизора" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="partner_subscription_percentage" class="form-control" placeholder="Процент подписки партнера" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="manager_subscription_percentage" class="form-control" placeholder="Процент подписки менеджера" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="supervisor_subscription_percentage" class="form-control" placeholder="Процент подписки супервизора" required>
                </div>
                <div class="form-group">
                    <input type="checkbox" name="restricted" id="restricted">
                    <label for="restricted">Партнера с этим тарифом нельзя назначать менеджеру или супервизору</label>
                </div>
                <button type="submit" class="btn btn-primary">Создать тариф</button>
            </form>
        </div>
    </body>
    </html>
    ''')



@app.route('/tariffs')
@login_required
@role_required('admin')
def list_tariffs():
    tariffs = Tariff.query.all()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Тарифы</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .tariff-list {
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .tariff-list h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .tariff-list ul {
                list-style: none;
                padding: 0;
            }
            .tariff-list li {
                padding: 10px;
                border-bottom: 1px solid #ddd;
            }
            .tariff-list li:last-child {
                border-bottom: none;
            }
            .tariff-list a {
                color: #007bff;
            }
            .tariff-list a:hover {
                text-decoration: underline;
            }
            .btn-back {
                display: block;
                margin: 20px auto;
                width: 100px;
            }
        </style>
    </head>
    <body>
        <div class="tariff-list">
            <h1>Тарифы</h1>
            <ul>
                {% for tariff in tariffs %}
                <li>{{ tariff.name }} - <a href="{{ url_for('edit_tariff', tariff_id=tariff.id) }}">Редактировать</a> - <a href="{{ url_for('delete_tariff', tariff_id=tariff.id) }}">Удалить</a></li>
                {% endfor %}
            </ul>
            <a href="/admin" class="btn btn-secondary btn-back">Назад</a>
        </div>
    </body>
    </html>
    ''', tariffs=tariffs)

@app.route('/edit_tariff/<int:tariff_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_tariff(tariff_id):
    tariff = Tariff.query.get_or_404(tariff_id)
    if request.method == 'POST':
        tariff.name = request.form['name']
        tariff.base_price = float(request.form['base_price'])
        tariff.partner_initial_payment = float(request.form['partner_initial_payment'])
        tariff.manager_initial_payment = float(request.form['manager_initial_payment'])
        tariff.supervisor_initial_payment = float(request.form['supervisor_initial_payment'])
        tariff.partner_subscription_percentage = float(request.form['partner_subscription_percentage'])
        tariff.manager_subscription_percentage = float(request.form['manager_subscription_percentage'])
        tariff.supervisor_subscription_percentage = float(request.form['supervisor_subscription_percentage'])
        tariff.restricted = 'restricted' in request.form
        db.session.commit()
        flash('Тариф успешно обновлен')
        return redirect(url_for('list_tariffs'))

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Редактировать тариф</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .form-container {
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .form-container h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .form-group {
                margin-bottom: 15px;
            }
            .btn-primary {
                display: block;
                width: 100%;
            }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h1>Редактировать тариф</h1>
            <form method="POST">
                <!-- Существующие поля формы -->
                <div class="form-group">
                    <input type="text" name="name" class="form-control" placeholder="Название тарифа" value="{{ tariff.name }}" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="base_price" class="form-control" placeholder="Базовая цена" value="{{ tariff.base_price }}" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="partner_initial_payment" class="form-control" placeholder="Первоначальный платеж партнера" value="{{ tariff.partner_initial_payment }}" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="manager_initial_payment" class="form-control" placeholder="Первоначальный платеж менеджера" value="{{ tariff.manager_initial_payment }}" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="supervisor_initial_payment" class="form-control" placeholder="Первоначальный платеж супервизора" value="{{ tariff.supervisor_initial_payment }}" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="partner_subscription_percentage" class="form-control" placeholder="Процент подписки партнера" value="{{ tariff.partner_subscription_percentage }}" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="manager_subscription_percentage" class="form-control" placeholder="Процент подписки менеджера" value="{{ tariff.manager_subscription_percentage }}" required>
                </div>
                <div class="form-group">
                    <input type="number" step="0.01" name="supervisor_subscription_percentage" class="form-control" placeholder="Процент подписки супервизора" value="{{ tariff.supervisor_subscription_percentage }}" required>
                </div>
                <div class="form-group form-check">
                    <input type="checkbox" class="form-check-input" id="restricted" name="restricted" {% if tariff.restricted %}checked{% endif %}>
                    <label class="form-check-label" for="restricted">Партнера с этим тарифом нельзя назначать менеджеру или супервизору</label>
                </div>
                <button type="submit" class="btn btn-primary">Обновить тариф</button>
            </form>
        </div>
    </body>
    </html>
    ''', tariff=tariff)


@app.route('/delete_tariff/<int:tariff_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def delete_tariff(tariff_id):
    tariff = Tariff.query.get_or_404(tariff_id)
    db.session.delete(tariff)
    db.session.commit()
    flash('Тариф удален')
    return redirect(url_for('list_tariffs'))

@app.route('/assign_partner_manager', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def assign_partner_manager():
    partners = User.query.filter_by(role='partner').all()
    managers = User.query.filter_by(role='manager').all()

    if request.method == 'POST':
        partner_id = request.form['partner_id']
        manager_id = request.form['manager_id']

        association = PartnerManagerAssociation(partner_id=partner_id, manager_id=manager_id)
        db.session.add(association)
        db.session.commit()

        flash('Партнер успешно назначен менеджеру')
        return redirect(url_for('assign_partner_manager'))

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Назначить партнера менеджеру</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .form-container {
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                background-color: #f9f9f9;
            }
            .form-container h1 {
                text-align: center;
                margin-bottom: 20px;
            }
            .form-group {
                margin-bottom: 15px;
            }
            .btn-primary {
                display: block;
                width: 100%;
            }
        </style>
    </head>
    <body>
        <div class="form-container">
            <h1>Назначить партнера менеджеру</h1>
            <form method="POST">
                <div class="form-group">
                    <label for="partner_id">Партнер</label>
                    <select id="partner_id" name="partner_id" class="form-control" required>
                        {% for partner in partners %}
                        <option value="{{ partner.id }}">{{ partner.username }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="form-group">
                    <label for="manager_id">Менеджер</label>
                    <select id="manager_id" name="manager_id" class="form-control" required>
                        {% for manager in managers %}
                        <option value="{{ manager.id }}">{{ manager.username }}</option>
                        {% endfor %}
                    </select>
                </div>
                <button type="submit" class="btn btn-primary">Назначить</button>
            </form>
        </div>
    </body>
    </html>
    ''', partners=partners, managers=managers)






def update_key_status():
    conn = sqlite3.connect('/root/miner-data/file.db')
    cursor = conn.cursor()
    current_time = datetime.now()
    cursor.execute("SELECT id, key_name, end_date FROM user_keys WHERE status != 'inactive'")
    keys = cursor.fetchall()

    for key in keys:
        key_id = key[0]
        key_name = key[1]
        end_date_str = key[2]

        if end_date_str is None:
            continue  # Пропуск записей без даты окончания

        end_date = datetime.strptime(end_date_str, '%Y-%m-%d %H:%M:%S')

        if end_date < current_time:
            new_key_name = f"(OFF) {key_name}" if not key_name.startswith("(OFF)") else key_name
            logger.info(f"Префикс (OFF) для ключа ID {key_id}: старое имя '{key_name}', новое имя '{new_key_name}'")
            cursor.execute("UPDATE user_keys SET status=?, key_name=? WHERE id=?", ('inactive', new_key_name, key_id))
            logger.info(f"Key ID {key_id}: статус обновлен на 'inactive', имя ключа обновлено на '{new_key_name}'")
    
    conn.commit()
    conn.close()

# Настройка планировщика задач
scheduler = BackgroundScheduler()
scheduler.add_job(update_key_status, 'interval', minutes=60)
scheduler.start()

@app.route('/pay', methods=['GET', 'POST'])
def pay():
    if request.method == 'POST':
        key = request.form['key']
        duration = int(request.form['duration'])
        
        conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_keys WHERE key=?", (key,))
        user_key = cursor.fetchone()
        
        if not user_key:
            flash('Такого ключа не существует', 'error')
            return redirect(url_for('pay'))
        
        if user_key[7] not in ['new', 'active', 'inactive']:
            flash('Неверный статус ключа', 'error')
            return redirect(url_for('pay'))

        extension_days = get_extension_days(duration)
        amount = get_amount(duration)
        
        # Создание платежа в YooKassa
        try:
            payment = yookassa.Payment.create({
                "amount": {
                    "value": amount,
                    "currency": "RUB"
                },
                "confirmation": {
                    "type": "redirect",
                    "return_url": url_for('payment_success', key=key, duration=duration, _external=True)
                },
                "capture": True,
                "description": f"Продление ключа {key} на {extension_days} дней"
            })
        except UnauthorizedError as e:
            app.logger.error(f"Ошибка авторизации: {e}")
            flash('Ошибка авторизации при создании платежа. Пожалуйста, проверьте учетные данные.', 'error')
            return redirect(url_for('pay'))
        
        # Добавляем payment_id в таблицу payment
        new_payment = Payment(
            user_id=user_key[1],
            tariff_id=user_key[8],
            amount=amount,
            extension_days=extension_days,
            key=key,
            payment_id=payment.id
        )
        db.session.add(new_payment)
        db.session.commit()
        
        # Добавляем payment_id в сессию
        session['payment_id'] = payment.id
        app.logger.info(f"Создан платеж: {payment.id}, сумма: {amount}, для ключа: {key}")
        return redirect(payment.confirmation.confirmation_url)


    return render_template_string('''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOVA MONITORING - Ваш инструмент для мониторинга майнеров</title>
    
    <meta name="description" content="SOVA MONITORING — это мощный инструмент для мониторинга ваших майнеров. Реальное время, уведомления и оптимизация.">
    <meta name="keywords" content="майнинг, мониторинг, SOVA MONITORING, уведомления, оптимизация, реальное время">
    <meta name="author" content="SOVA MONITORING">

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" integrity="sha384-k6Rqe9ComboEhc7F/T3JPmxcoAw7OV5y4M6v4EaBR4z7lUwDK6MFdRB4Gk5gkW5y+V" crossorigin="anonymous">
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    
    <style>
        .navbar-brand {
            display: flex;
            align-items: center;
        }
        .navbar-brand img {
            max-height: 40px;
            margin-right: 10px;
        }
        .navbar, footer {
            background-color: #306AA5;
        }
        .text-warning {
            color: #ffc107!important;
        }

        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        .container {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container-form {
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
            margin: 20px;
        }
        .container-form h1 {
            text-align: center;
            color: #333;
            margin-bottom: 20px;
        }
        .container-form form {
            display: flex;
            flex-direction: column;
        }
        .container-form label {
            margin-bottom: 5px;
            color: #555;
        }
        .container-form input, .container-form select, .container-form button {
            margin-bottom: 15px;
            padding: 10px;
            border-radius: 4px;
            border: 1px solid #ddd;
            font-size: 16px;
        }
        .container-form button {
            background-color: #28a745;
            color: #fff;
            border: none;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        .container-form button:hover {
            background-color: #218838;
        }
        .flashes {
            list-style: none;
            padding: 0;
            margin: 0 0 15px 0;
        }
        .flashes li {
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 10px;
            font-size: 14px;
        }
        .flashes .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .flashes .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        footer {
            background-color: #306AA5;
            color: white;
            padding: 10px 0;
            text-align: center;
            width: 100%;
        }
        .footer-links a {
            color: white;
            margin: 0 10px;
        }
        @media (max-width: 768px) {
            .container-form {
                max-width: 100%;
                margin-top: 20px;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <a class="navbar-brand" href="https://sovamonitoring.com/">
            <img src="https://sovamonitoring.com/static/Sova_logo.jpg" alt="Логотип SOVA MONITORING" style="height: 50px;">
            SOVA MONITORING
        </a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav mr-auto">
                <li class="nav-item">
                    <a class="nav-link" href="https://sovamonitoring.com/">Главная</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="https://sovamonitoring.com/information">Информация</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="https://sovamonitoring.com/contacts">Контакты</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="https://sovamonitoring.com/shop">Купить устройство</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link text-warning" href="https://sovamonitoring.com/download">Скачать на телефон</a>
                </li>
            </ul>
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link btn btn-success" href="/pay">Онлайн оплата</a>
                </li>
            </ul>
        </div>
    </nav>
    <div class="container">
        <div class="container-form">
            <h1>Оплата ключа</h1>
            <form method="post">
                <label for="key">Введите ключ:</label>
                <input type="text" id="key" name="key" required>

                <label for="duration">Выберите период оплаты:</label>
                <select id="duration" name="duration" required>
                    <option value="1">1 месяц - 700 руб.</option>
                    <option value="3">3 месяца - 1950 руб.</option>
                    <option value="6">6 месяцев - 3600 руб.</option>
                    <option value="12">1 год - 6000 руб.</option>
                </select>

                <button type="submit">Оплатить</button>
            </form>
            {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <ul class="flashes">
                {% for category, message in messages %}
                    <li class="alert alert-{{ category }}">{{ message }}</li>
                {% endfor %}
                </ul>
            {% endif %}
            {% endwith %}
        </div>
    </div>
    <footer class="text-white text-center py-2">
        <div class="container">
            <div class="row">
                <div class="col-12">
                    <p>
                        Email: <a href="mailto:demdas@yandex.ru" class="text-white">demdas@yandex.ru</a> | 
                        <a href="https://sovamonitoring.com/privacy-policy" class="text-white">Privacy Policy</a> | 
                        <a href="https://sovamonitoring.com/delete_account" class="text-white">Удаление аккаунта</a>
                    </p>
                </div>
                <div class="col-12">
                    <p>&copy; 2024 SOVA MONITORING. Все права защищены.</p>
                </div>
            </div>
        </div>
    </footer>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
    ''')



@app.route('/payment_success', methods=['GET', 'POST'])
def payment_success():
    key = request.args.get('key') if request.method == 'GET' else request.form.get('key')
    duration = request.args.get('duration') if request.method == 'GET' else request.form.get('duration')
    payment_id = session.get('payment_id')

    if not key or not duration or not payment_id:
        flash('Отсутствуют необходимые параметры для завершения оплаты', 'error')
        return redirect(url_for('pay'))

    # Проверка статуса оплаты через YooKassa API
    payment = yookassa.Payment.find_one(payment_id)
    if payment.status != 'succeeded':
        flash('Оплата не была завершена успешно. Пожалуйста, попробуйте еще раз.', 'error')
        return redirect(url_for('pay'))

    flash('Платеж успешно завершен. Обработка платежа будет выполнена при получении подтверждения.', 'success')
    return redirect(url_for('pay'))

@app.route('/yookassa_notification', methods=['POST'])
def yookassa_notification():
    notification_data = request.json
    app.logger.info(f"Получено уведомление от YooKassa: {notification_data}")
    
    if 'event' not in notification_data or notification_data['event'] != 'payment.succeeded':
        return jsonify({'status': 'ignored'})
    
    payment_id = notification_data['object']['id']
    process_successful_payment(payment_id)
    return jsonify({'status': 'processed'})

def process_successful_payment(payment_id):
    # Подключение к базе данных пользователей
    user_db_path = os.path.join(BASE_DIR, 'instance/users.db')
    conn = sqlite3.connect(user_db_path)
    cursor = conn.cursor()
    
    # Найдите платеж по payment_id
    cursor.execute("SELECT * FROM payment WHERE payment_id=?", (payment_id,))
    payment_record = cursor.fetchone()
    
    if not payment_record:
        app.logger.error(f"Не удалось найти платеж с payment_id: {payment_id}")
        return
    
    if payment_record[8]:  # Проверка если processed уже True
        app.logger.info(f"Платеж с payment_id: {payment_id} уже был обработан")
        return

    key = payment_record[6]  # Индекс может варьироваться в зависимости от структуры таблицы
    duration = payment_record[4]

    conn_secondary = sqlite3.connect(SECONDARY_DATABASE_PATH)
    cursor_secondary = conn_secondary.cursor()
    cursor_secondary.execute("SELECT * FROM user_keys WHERE key=?", (key,))
    user_key = cursor_secondary.fetchone()
    
    if not user_key:
        app.logger.error(f"Не удалось найти ключ: {key}")
        return

    extension_days = duration
    new_end_date = calculate_new_end_date(user_key[6], extension_days)

    # Проверка текущего статуса ключа и определение нового статуса
    current_status = user_key[7]
    new_status = 'active' if current_status == 'inactive' else current_status
    app.logger.info(f"Обновление ключа: {key}, старый статус: {current_status}, новый статус: {new_status}")

    # Удаление префикса (OFF) из key_name, если он есть
    key_name = user_key[3]
    new_key_name = key_name.replace("(OFF) ", "") if key_name and key_name.startswith("(OFF)") else key_name

    # Обновление end_date, status и key_name
    cursor_secondary.execute("UPDATE user_keys SET end_date=?, status=?, key_name=? WHERE key=?", 
                             (new_end_date.strftime('%Y-%m-%d %H:%M:%S'), new_status, new_key_name, key))
    conn_secondary.commit()
    
    # Проверка обновления
    cursor_secondary.execute("SELECT status, key_name FROM user_keys WHERE key=?", (key,))
    updated_status, updated_key_name = cursor_secondary.fetchone()
    app.logger.info(f"Статус после обновления: {updated_status}, имя ключа после обновления: {updated_key_name}")
    
    # Обновляем запись в базе данных, помечая платеж как обработанный
    cursor.execute("UPDATE payment SET processed = 1 WHERE payment_id = ?", (payment_id,))
    conn.commit()

    conn_secondary.close()
    conn.close()

def get_extension_days(duration):
    if duration == 1:
        return 30
    elif duration == 3:
        return 90
    elif duration == 6:
        return 180
    elif duration == 12:
        return 365
    return 0

def get_amount(duration):
    if duration == 1:
        return 700
    elif duration == 3:
        return 1950
    elif duration == 6:
        return 3600
    elif duration == 12:
        return 6000
    return 0

def calculate_new_end_date(current_end_date, extension_days):
    if current_end_date:
        end_date = datetime.strptime(current_end_date, '%Y-%m-%d %H:%M:%S')
    else:
        end_date = datetime.now()
    
    # Определяем начальную точку отсчета: текущая дата или дата окончания ключа
    start_date = max(datetime.now(), end_date)
    new_end_date = start_date + timedelta(days=extension_days)
    return new_end_date



@app.route('/app/check-update', methods=['GET'])
def check_update():
    # Получаем версию, которая пришла от клиента
    current_version = request.args.get('version')
    
    # Логируем версию для отладки
    print(f"Received version from client: {current_version}")
    
    if not current_version:
        print("Error: Version is missing from the request")
        return jsonify({"error": "Version is required"}), 400

    # Проверяем, требуется ли обновление, и логируем результат
    update_required = is_update_required(current_version)
    print(f"Update required: {update_required}")
    
    # Возвращаем результат клиенту
    return jsonify({"update_required": update_required})


if __name__ == '__main__':
    read_db_path = SECONDARY_DATABASE_PATH
    write_db_path = '/root/cabinet/instance/metrics.db'
    thread = threading.Thread(target=periodic_save, args=(read_db_path, write_db_path, 3600))
    thread.start()

    # Инициализация и запуск фонового процесса
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=sync_keys, trigger="interval", minutes=0.5)
    scheduler.start()

    # Shut down the scheduler when exiting the app
    atexit.register(lambda: scheduler.shutdown())
    
    app.run(host='0.0.0.0', port=5001)