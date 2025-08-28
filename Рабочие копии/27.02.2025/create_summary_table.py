import sqlite3
import pandas as pd
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request, redirect, url_for, flash, session, make_response, g, render_template
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
from phone_utils import send_sms
from email_utils import send_email
import jwt
from sqlalchemy.orm import Session
from phone_utils import send_sms
import re
from random import randint
import math
from collections import Counter
import requests



# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Настройки YooKassa
yookassa.Configuration.account_id = '396396'
yookassa.Configuration.secret_key = 'live_s8H0Ts0UqGDXUKjwszCZBA-Jy049jFqWGjKQ8P0_gno'

# Установите путь к основной базе данных
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'instance/users.db')

# Установите путь ко второй базе данных
SECONDARY_DATABASE_PATH = os.path.join(BASE_DIR, '/root/miner-data/file.db')

# Путь к базе данных с покупками устройств (orders.db)
DATABASE = os.path.join(BASE_DIR, 'instance', 'orders.db')


app = Flask(__name__)

app.config['JSON_AS_ASCII'] = False


# Установим SECRET_KEY для Flask-сессий и JWT
app.config['SECRET_KEY'] = "6f68bd57715ae163e42efec24e698d0f"
app.secret_key = app.config['SECRET_KEY']  # Убедимся, что Flask использует тот же секретный ключ
JWT_SECRET_KEY = app.config['SECRET_KEY']  # Для JWT-энкодинга и декодинга

# Определим SECRET_KEY на уровне модуля
SECRET_KEY = app.config['SECRET_KEY']


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DATABASE_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
migrate = Migrate(app, db)


# Вспомогательная функция для нормализации номера телефона
def normalize_phone_number(phone_number):
    return re.sub(r'\D', '', phone_number)

# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(150), nullable=True)
    role = db.Column(db.String(50), nullable=False)
    reset_token = db.Column(db.String(150), nullable=True)
    tariff_id = db.Column(db.Integer, db.ForeignKey('tariff.id'), nullable=True)
    tariff = db.relationship('Tariff', backref=db.backref('users', lazy=True))
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(250), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    verification_code = db.Column(db.String(10), nullable=True)
    code_time = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    balance = db.Column(db.Float, default=0.0)  # Добавленное поле balance
    platform_id = db.Column(db.String(50), nullable=True)



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


# Генерация JWT токена с ролью пользователя
def generate_jwt_token(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=8760)  # Токен истекает через 1 год
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
    print(f"Generated JWT token: {token}")
    return token



# Декоратор для проверки аутентификации с токеном
def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        # Получение токена из cookies или заголовков
        if 'token' in request.cookies:
            token = request.cookies.get('token')
            print(f"Token from cookie: {token}")
        elif 'Authorization' in request.headers:
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(" ")[1]  # Убираем "Bearer "
            print(f"Token from Authorization header: {token}")

        if not token:
            print("No token found. Redirecting to login.")
            flash("Требуется вход в систему.")
            return redirect(url_for('login'))

        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            print(f"Decoded JWT payload: {payload}")
            user_id = payload['user_id']
            user = db.session.get(User, user_id)
            if user:
                g.user = user  # Сохраняем пользователя в объекте g
                print(f"Authenticated user: {g.user.username}, Role: {g.user.role}")
                return f(*args, **kwargs)
            else:
                print("User not found in database. Redirecting to login.")
                flash("Пользователь не найден.")
                return redirect(url_for('login'))
        except jwt.ExpiredSignatureError:
            print("Token has expired. Redirecting to login.")
            flash("Срок действия токена истек, пожалуйста, войдите снова.")
            return redirect(url_for('login'))
        except jwt.InvalidTokenError as e:
            print(f"Invalid token error: {e}. Redirecting to login.")
            flash("Неверный токен, пожалуйста, войдите снова.")
            return redirect(url_for('login'))

    return decorated_function

# Декоратор для проверки роли пользователя
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            print(f"User role: {getattr(g.user, 'role', None)}, Required roles: {roles}")
            if hasattr(g, 'user') and g.user.role in roles:
                return f(*args, **kwargs)
            
            # Логирование и отображение сообщения об отсутствии доступа
            print("User does not have required role. Showing access denied message.")
            flash("У вас нет доступа к этой странице.")

            # HTML-шаблон с сообщением об ограничении доступа и кнопкой "На главную"
            access_denied_template = '''
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Доступ запрещен</title>
                <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
                <style>
                    .container {
                        max-width: 500px;
                        margin: 50px auto;
                        text-align: center;
                    }
                    .btn-back {
                        margin-top: 20px;
                        padding: 10px 20px;
                        background-color: #4CAF50;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                        display: inline-block;
                    }
                    .btn-back:hover {
                        background-color: #45a049;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Доступ запрещен</h1>
                    <p>У вас нет доступа к этой странице.</p>
                    <a href="{{ url_for('dashboard') }}" class="btn-back">На главную</a>
                </div>
            </body>
            </html>
            '''
            # Отображение страницы с кнопкой "На главную"
            return render_template_string(access_denied_template), 403
        return decorated_function
    return decorator

# Маршрут для создания пользователя при запуске
with app.app_context():
    db.create_all()
    def add_user_if_not_exists(username, email, password, role, phone=None):
        if not User.query.filter_by(username=username).first():
            user = User(username=username, email=email, password=generate_password_hash(password, method='sha256'), role=role, phone=phone)
            db.session.add(user)
            db.session.commit()
    add_user_if_not_exists('admin', '', 'admin', 'admin', phone='79086640880')  # Добавляем номер телефона к администратору
    add_user_if_not_exists('partner', '', 'partner', 'partner')
    add_user_if_not_exists('manager', '', 'manager', 'manager')


# Главная страница с проверкой аутентификации
@app.route('/')
def home():
    return redirect(url_for('dashboard'))


# Маршрут для входа по номеру телефона
@app.route('/login', methods=['GET', 'POST'])
def login():
    is_api_request = request.headers.get('Accept') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if request.method == 'POST':
        phone_number = request.form.get('phone')
        platform_id = request.form.get('platform_id')  # Получаем platform_id из запроса, если есть

        if phone_number:
            phone_number = normalize_phone_number(phone_number)
            phone_number = ''.join(filter(str.isdigit, phone_number))
            if phone_number.startswith('8'):
                phone_number = '7' + phone_number[1:]
            elif not phone_number.startswith('7'):
                phone_number = '7' + phone_number

            print(f"Processing login for phone number: {phone_number}")

            # Поиск пользователя
            user = User.query.filter_by(phone=phone_number).first()

            # Генерация кода подтверждения
            if phone_number == "79991111111":
                verification_code = "123456"
            else:
                verification_code = str(randint(1000, 9999))
            current_time = datetime.utcnow()

            if user:
                user.verification_code = verification_code
                user.code_time = current_time
                # Обновляем platform_id, если оно передано
                if platform_id and not user.platform_id:
                    user.platform_id = platform_id
                db.session.commit()
                print(f"Generated verification code (existing user): {verification_code}")
            else:
                # Создание нового пользователя
                username = "partner_" + phone_number[-4:]
                user = User(
                    username=username,
                    email='',
                    password='',
                    role='partner',
                    phone=phone_number,
                    verification_code=verification_code,
                    code_time=current_time,
                    platform_id=platform_id  # Устанавливаем platform_id при создании
                )
                db.session.add(user)
                db.session.commit()
                print(f"Generated verification code (new user): {verification_code}")

            # Отправка SMS
            try:
                if phone_number == "79991111111":
                    print(f"Test user detected. Skipping SMS sending.")
                else:
                    send_sms(phone_number, f"{verification_code} — ваш код для входа в панель партнера Сова Мониторинг")
                    print(f"SMS sent to {phone_number} with code {verification_code}")
            except Exception as e:
                print(f"Failed to send SMS: {e}")
                if is_api_request:
                    return jsonify({'status': 'error', 'message': 'Error sending SMS. Please try again later.'}), 500
                flash('Ошибка при отправке SMS. Пожалуйста, попробуйте позже.')
                return redirect(url_for('login'))

            # Ответ в зависимости от типа запроса
            if is_api_request:
                return jsonify({'status': 'success', 'message': 'Verification code sent to your phone number.'}), 200
            else:
                flash('Код подтверждения отправлен на ваш номер телефона.')
                session['phone_number'] = phone_number
                return redirect(url_for('verify_phone_number'))
        else:
            if is_api_request:
                return jsonify({'status': 'error', 'message': 'Please enter your phone number.'}), 400
            flash('Введите номер телефона.')
            return redirect(url_for('login'))

    return render_template_string('''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
        <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/inputmask@5.0.6/dist/jquery.inputmask.min.js"></script>
        <script>
            $(document).ready(function(){
                $('input[name="phone"]').inputmask({
                    mask: "+7 (999) 999-99-99",
                    clearMaskOnLostFocus: false,
                    showMaskOnHover: false,
                    showMaskOnFocus: true
                });
            });
        </script>
    </head>
    <body>
        <div class="login-container">
            <h1>Вход</h1>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert alert-success" role="alert">
                  {% for message in messages %}
                    <p>{{ message }}</p>
                  {% endfor %}
                </div>
              {% endif %}
            {% endwith %}
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="phone" class="form-control" placeholder="+7 (___) ___-__-__" required>
                </div>
                <button type="submit" class="btn btn-primary">Получить код</button>
            </form>
        </div>
    </body>
    </html>
    ''')

# Маршрут для проверки кода и авторизации
@app.route('/verify-phone-number', methods=['GET', 'POST'])
def verify_phone_number():
    is_api_request = request.headers.get('Accept') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if request.method == 'GET' and not is_api_request:
        # Показать страницу для ввода кода, если это GET-запрос с веба
        return render_template_string('''
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Подтверждение номера</title>
            <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
            <style>
                .verify-container {
                    max-width: 400px;
                    margin: 50px auto;
                    padding: 20px;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    background-color: #f9f9f9;
                }
                .verify-container h1 {
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
            <div class="verify-container">
                <h1>Подтверждение номера</h1>
                {% with messages = get_flashed_messages() %}
                  {% if messages %}
                    <div class="alert alert-danger" role="alert">
                      {% for message in messages %}
                        <p>{{ message }}</p>
                      {% endfor %}
                    </div>
                  {% endif %}
                {% endwith %}
                <form method="POST">
                    <div class="form-group">
                        <input type="text" name="code" class="form-control" placeholder="Код подтверждения" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Войти</button>
                </form>
            </div>
        </body>
        </html>
        ''')

    # Обработка POST-запроса для проверки кода
    if is_api_request:
        phone_number = request.json.get('phone')
        code = request.json.get('code')
    else:
        phone_number = session.get('phone_number')
        code = request.form.get('code')

    # Нормализация номера телефона
    if phone_number:
        phone_number = ''.join(filter(str.isdigit, phone_number))
        if phone_number.startswith('8'):
            phone_number = '7' + phone_number[1:]
        elif not phone_number.startswith('7'):
            phone_number = '7' + phone_number

    if not phone_number or not code:
        if is_api_request:
            return jsonify({'status': 'error', 'message': 'Phone number and code are required.'}), 400
        flash('Введите номер телефона и код подтверждения.')
        return redirect(url_for('login'))

    print(f"Verifying phone number: {phone_number} with code: {code}")
    user = User.query.filter_by(phone=phone_number).first()

    if user is None:
        print("No user found for this phone number")
        if is_api_request:
            return jsonify({'status': 'error', 'message': 'No user found with this phone number.'}), 404
        flash('Пользователь с таким номером телефона не найден.')
        return redirect(url_for('login'))

    if user.verification_code == code:
        user.verification_code = None
        user.code_time = None
        db.session.commit()
        print("Verification successful")

        jwt_token = generate_jwt_token(user.id, user.role)
        print(f"Generated JWT token: {jwt_token}")

        if is_api_request:
            return jsonify({'status': 'success', 'message': 'Verification successful.', 'token': jwt_token}), 200
        else:
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('token', jwt_token, httponly=True, max_age=31536000)
            session.pop('phone_number', None)
            return response
    else:
        print("Wrong verification code entered")
        if is_api_request:
            return jsonify({'status': 'error', 'message': 'Incorrect verification code.'}), 400
        flash('Неверный код подтверждения.')
        return redirect(url_for('verify_phone_number'))





# Маршрут для входа с выводом сообщений
@app.route('/old_login', methods=['GET', 'POST'])
def old_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            token = generate_jwt_token(user.id, user.role)
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('token', token, httponly=True)
            return response

        flash('Неверный email или пароль')
        return redirect(url_for('login'))

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Вход</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .login-container { max-width: 400px; margin: 50px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); background-color: #f9f9f9; }
            .login-container h1 { text-align: center; margin-bottom: 20px; }
            .form-group { margin-bottom: 15px; }
            .btn-primary { display: block; width: 100%; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>Вход</h1>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert alert-success" role="alert">
                  {% for message in messages %}
                    <p>{{ message }}</p>
                  {% endfor %}
                </div>
              {% endif %}
            {% endwith %}
            <form method="POST">
                <div class="form-group"><input type="email" name="email" class="form-control" placeholder="Email" required></div>
                <div class="form-group"><input type="password" name="password" class="form-control" placeholder="Пароль" required></div>
                <button type="submit" class="btn btn-primary">Войти</button>
                <a href="{{ url_for('reset_password') }}">Забыли пароль?</a><br>
                <a href="{{ url_for('register') }}">Зарегистрироваться</a>
            </form>
        </div>
    </body>
    </html>
    ''')


@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('token')  # Удаляем токен из cookies
    flash('Вы вышли из системы.')
    return response


# Маршрут /dashboard
@app.route('/dashboard')
@auth_required
@role_required('admin', 'partner', 'manager', 'supervisor', 'user')  # Добавили 'user' в разрешенные роли
def dashboard():
    print(f"Accessing dashboard with user: {g.user.username}, Role: {g.user.role}")
    dashboard_html = '''
    <h1>Панель управления</h1>
    <a href="/logout">Выйти</a>
    <a href="https://cabinet.sovamonitoring.com/daily_metrics">Ежедневные метрики</a>
    <a href="/partner_statistics">Статистика по партнёрам</a>
    '''
    # Отображаем только те ссылки, которые соответствуют роли пользователя
    if g.user.role == 'admin':
        dashboard_html += '<a href="/admin">Панель администратора</a>'
        dashboard_html += '<a href="/manage_statuses">Управление</a>'
        dashboard_html += '<a href="/money">Финансы</a>'
    elif g.user.role == 'partner':
        dashboard_html += '<a href="/partner">Панель партнёра</a>'
    elif g.user.role == 'manager':
        dashboard_html += '<a href="/manager">Панель менеджера</a>'
    elif g.user.role == 'supervisor':
        dashboard_html += '<a href="/supervisor">Панель супервизора</a>'
    elif g.user.role == 'user':
        dashboard_html += '<a href="/user">Панель пользователя</a>'

    return render_template_string('''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
            @media (max-width: 576px) {
                .dashboard {
                    padding: 15px;
                    margin: 20px;
                    width: 90%;
                }
                .dashboard h1 {
                    font-size: 1.5rem;
                    margin-bottom: 15px;
                }
                .dashboard a {
                    font-size: 0.9rem;
                    padding: 8px;
                }
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

        # Преобразование даты, если previous_end_date передан как строка
        if isinstance(previous_end_date, str):
            previous_end_date = datetime.strptime(previous_end_date, '%Y-%m-%d %H:%M:%S')

        # Даты для расчёта периода продления
        start_date = datetime.strptime(user_key.start_date, '%Y-%m-%d %H:%M:%S')
        end_date = datetime.strptime(user_key.end_date, '%Y-%m-%d %H:%M:%S')

        # Текущая дата используется для проверки актуальности
        current_date = datetime.now()
        effective_start_date = max(previous_end_date, current_date)

        # Точный расчёт количества дней продления
        extension_duration = round((end_date - effective_start_date).total_seconds() / (24 * 3600))

        if extension_duration <= 0:
            return

        # Расчет заработка с использованием точного количества дней продления
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

        # Начисление для менеджера (если существует)
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
                        description=f"Заработок менеджера за продление ключа {user_key.key} на {extension_duration} дней, с {effective_start_date.strftime('%Y-%m-%d')} по {end_date.strftime('%Y-%m-%d')}, по тарифу {manager_tariff.name}"
                    ))

        # Начисление для супервизора (если существует)
        supervisor = None
        if manager:
            supervisor_association = ManagerSupervisorAssociation.query.filter_by(manager_id=manager.id).first()
            if supervisor_association:
                supervisor = User.query.filter_by(id=supervisor_association.supervisor_id).first()
                if supervisor:
                    supervisor_tariff = Tariff.query.filter_by(id=supervisor.tariff_id).first()
                    if supervisor_tariff:
                        supervisor_earning = subscription_price * (supervisor_tariff.supervisor_subscription_percentage / 100)
                        db.session.add(Earning(
                            user_id=supervisor.id,
                            key_id=user_key.id,
                            amount=round(supervisor_earning, 1),
                            description=f"Заработок супервизора за продление ключа {user_key.key} на {extension_duration} дней, с {effective_start_date.strftime('%Y-%m-%d')} по {end_date.strftime('%Y-%m-%d')}, по тарифу {supervisor_tariff.name}"
                        ))

        # Сохранение всех начислений в базе данных
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




@app.route('/api/device-purchase', methods=['POST'])
def device_purchase():
    """Маршрут для обработки уведомлений от Yookassa."""
    try:
        logging.info(f"Headers: {request.headers}")
        logging.info(f"Body: {request.data.decode('utf-8')}")

        # Парсим JSON
        data = request.json

        if not data or 'event' not in data or 'object' not in data:
            return jsonify({'error': 'Invalid payload structure'}), 400

        # Проверяем тип события
        if data['event'] != 'payment.succeeded':
            return jsonify({'error': 'Unhandled event type'}), 200

        payment_object = data['object']
        metadata = payment_object.get('metadata', {})

        # Проверяем наличие обязательных полей
        required_metadata_fields = ['tilda_orderid', 'phone', 'email']
        missing_fields = [field for field in required_metadata_fields if field not in metadata]
        if missing_fields:
            return jsonify({'error': 'Missing required fields in metadata', 'fields': missing_fields}), 400

        # Извлекаем данные
        order_id = metadata['tilda_orderid']
        device_id = metadata.get('device_id', 'unknown')  # Укажите значение по умолчанию, если device_id отсутствует
        amount = payment_object['amount']['value']
        status = payment_object['status']
        phone_number = metadata['phone']
        email = metadata['email']
        delivery_address = metadata.get('delivery_address', None)
        product_name = metadata.get('product_name', "Unknown product")
        subscription_end_date = metadata.get('subscription_end_date', None)
        platform_id = metadata.get('platform_id', None)

        # Сохраняем данные в базе
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO orders (
                order_id, device_id, amount, status, phone_number, email, 
                delivery_address, product_name, subscription_end_date, platform_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (order_id, device_id, amount, status, phone_number, email, 
              delivery_address, product_name, subscription_end_date, platform_id))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Order recorded successfully', 'order_id': order_id}), 201

    except Exception as e:
        logging.error(f"Error occurred: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

    




@app.route('/api/check-device', methods=['POST'])
def check_device():
    try:
        # Секретный ключ
        SECRET_API_KEY = "your_secret_api_key"

        # Получение API Key
        api_key = request.form.get('api_key') or request.headers.get('X-API-KEY')

        # Логирование данных
        print("Полученные данные:", request.form)
        print("Полученный API Key:", api_key)

        # Если данные тестовые, сразу возвращаем успешный ответ
        if request.form.get('test') == 'test':
            return jsonify({'status': 'test', 'message': 'Тестовые данные обработаны', 'redirect_url': ''}), 200

        # Проверка API Key
        if api_key != SECRET_API_KEY:
            return jsonify({'status': 'error', 'message': 'Unauthorized: Invalid API Key', 'redirect_url': ''}), 200

        # Получение ключа устройства
        key = request.form.get('key')
        if not key:
            return jsonify({'status': 'error', 'message': 'Device key is required', 'redirect_url': ''}), 200

        # Проверка устройства в базе данных
        conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_keys WHERE key=?", (key,))
        user_key = cursor.fetchone()

        if user_key:
            return jsonify({
                'status': 'success',
                'message': 'Устройство найдено',
                'redirect_url': 'https://yookassa.ru/checkout?key=' + key
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Устройство не найдено',
                'redirect_url': ''
            }), 200

    except Exception as e:
        print("Ошибка:", e)
        return jsonify({
            'status': 'error',
            'message': f'Ошибка: {str(e)}',
            'redirect_url': ''
        }), 200





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



@app.route('/api/partner_data', methods=['GET'])
@auth_required
@role_required('partner')
def get_partner_data():
    partner_id = g.user.id  # Получаем идентификатор партнёра
    partner = User.query.get(partner_id)

    # Получение ключей партнёра
    partner_keys = UserKey.query.filter_by(user_id=partner_id).all()

    # Подсчет устройств по статусам
    total_new_devices = sum(1 for key in partner_keys if key.status == 'new')
    total_active_devices = sum(1 for key in partner_keys if key.status == 'active')

    # Вычисление заработка
    partner_tariff = partner.tariff
    earnings = 0
    if partner_tariff:
        initial_earnings = Earning.query.filter(
            Earning.user_id == partner_id,
            Earning.description.like('Первоначальный заработок партнёра%')
        ).all()
        earnings = sum(e.amount for e in initial_earnings)

    # Получение информации о начислениях
    earnings_data = Earning.query.filter_by(user_id=partner_id).all()
    earnings_summary = sum(e.amount for e in earnings_data)

    # Получение назначенных тарифов
    assigned_tariffs = [partner_tariff] if partner_tariff else []

    # Функция для вычисления остатка дней
    def calculate_days_left(end_date):
        if end_date and isinstance(end_date, datetime):
            return (end_date - datetime.utcnow()).days
        return None

    # Подготовка данных для ответа
    data = {
        'partner': {
            'username': partner.username,
            'phone': partner.phone, 
            'platform_id': partner.platform_id,
        },
        'keys': [
            {
                'key': key.key,
                'status': key.status,
                'start_date': key.start_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(key.start_date, datetime) else key.start_date,
                'end_date': key.end_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(key.end_date, datetime) else key.end_date,
                'days_left': calculate_days_left(key.end_date),
            }
            for key in partner_keys
        ],
        'devices_summary': {
            'total_new_devices': total_new_devices,
            'total_active_devices': total_active_devices,
        },
        'earnings': {
            'initial_earnings': earnings,
            'total_earnings': earnings_summary,
        },
        'earnings_data': [
            {
                'id': e.id,
                'key_id': e.key_id,
                'amount': e.amount,
                'date': e.date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(e.date, datetime) else e.date,
                'description': e.description,
            }
            for e in earnings_data
        ],
        'assigned_tariffs': [
            {
                'id': t.id,
                'name': t.name,
                'base_price': t.base_price,
                'partner_initial_payment': t.partner_initial_payment,
                'partner_subscription_percentage': t.partner_subscription_percentage,
            }
            for t in assigned_tariffs
        ],
    }

    return jsonify(data)



@app.route('/manage_statuses', methods=['GET', 'POST'])
@auth_required
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
            <a href="/keys_management" class="btn btn-secondary btn-back">Управление клиентами</a>
            <a href="/devices" class="btn btn-secondary btn-back">Список устройств</a>
            <a href="/asic-functions" class="btn btn-secondary btn-back">Конфигуратор асика</a>
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
@auth_required
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
@auth_required
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
@auth_required
@role_required('admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_user':
            # Обновление основной информации пользователя
            user.username = request.form['username']
            user.email = request.form['email']
            user.phone = request.form['phone']
            user.address = request.form['address']
            user.notes = request.form['notes']
            
            # Обновление пароля, если он был введен
            if request.form['password']:
                user.password = generate_password_hash(request.form['password'], method='sha256')
            
            # Назначение роли и тарифа
            user.role = request.form['role']
            user.tariff_id = request.form['tariff_id']
            
            # Проверка ограничений тарифа для партнеров
            selected_tariff = Tariff.query.get(user.tariff_id)
            if user.role == 'partner' and selected_tariff and selected_tariff.restricted:
                if request.form.get('manager_id'):
                    flash('Партнера с этим тарифом нельзя назначать менеджеру или супервизору', 'danger')
                    return redirect(url_for('edit_user', user_id=user_id))

            # Обработка ассоциаций для менеджеров
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

            # Обработка ассоциаций для партнеров
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

            # Сохранение данных пользователя
            db.session.commit()
            flash('Пользователь успешно обновлен', 'success')
            return redirect(url_for('edit_user', user_id=user_id))

    # Получение данных для отображения в форме
    tariffs = Tariff.query.all()
    supervisors = User.query.filter_by(role='supervisor').all()
    managers = User.query.filter_by(role='manager').all()

    # Проверка текущих ассоциаций пользователя
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

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Редактировать пользователя</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <div class="d-flex justify-content-between align-items-center my-3">
                <a href="{{ url_for('list_users') }}" class="btn btn-secondary">Назад к списку пользователей</a>
                <a href="{{ url_for('manage_keys', user_id=user.id) }}" class="btn btn-info">Управление ключами</a>
            </div>
            <h1>Редактировать пользователя</h1>

            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    <div class="alert alert-success" role="alert">
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
                <div class="form-group">
                    <label for="tariff_id">Тариф</label>
                    <select id="tariff_id" name="tariff_id" class="form-control" required>
                        {% for tariff in tariffs %}
                        <option value="{{ tariff.id }}" {% if user.tariff_id == tariff.id %}selected{% endif %}>{{ tariff.name }}</option>
                        {% endfor %}
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

                <button type="submit" class="btn btn-primary mt-3">Сохранить изменения</button>
            </form>
        </div>
    </body>
    </html>
    ''', user=user, tariffs=tariffs, supervisors=supervisors, managers=managers,
    current_supervisor_id=current_supervisor_id, current_manager_id=current_manager_id)



# Маршрут для управления ключами пользователя
@app.route('/user/<int:user_id>/manage_keys', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def manage_keys(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_keys':
            new_keys = request.form.getlist('new_keys')
            operation_type = request.form.get('operation_type')  # Новое поле для типа операции
            amount = float(request.form.get('amount', 0))  # Новое поле для суммы
            if new_keys:
                # Добавляем ключи и сохраняем их, чтобы получить их ID
                add_keys(user_id, new_keys)
                db.session.commit()  # Сохраняем изменения в базе данных

                # Получаем объекты UserKey для добавленных ключей
                user_keys = UserKey.query.filter_by(user_id=user_id).filter(UserKey.key.in_(new_keys)).all()

                # Вызов функции для добавления операции с учетом нового функционала
                for user_key in user_keys:
                    add_operation(user_id, operation_type, user_key.id, amount)
            else:
                flash('Не выбрано ни одного ключа для добавления', 'warning')
        elif action == 'add_manual_key':
            manual_key = request.form.get('manual_key')
            if manual_key:
                add_manual_key(user_id, manual_key)
            else:
                flash('Введите корректный ключ для добавления вручную', 'warning')
        elif action == 'detach_keys':
            keys_to_detach = request.form.getlist('detach_keys')
            if keys_to_detach:
                # Собираем объекты ключей и их ID перед удалением
                user_keys = UserKey.query.filter_by(user_id=user_id).filter(UserKey.key.in_(keys_to_detach)).all()
                key_ids = [user_key.id for user_key in user_keys]

                # Удаляем ключи
                detach_keys(user_id, keys_to_detach)
                db.session.commit()  # Сохраняем изменения в базе данных

                # Корректируем баланс пользователя и удаляем операции
                for key_id in key_ids:
                    operation = UserOperation.query.filter_by(user_id=user_id, product_id=key_id).first()
                    if operation:
                        # Если операция типа 'sale' и статус 'confirmed', вычитаем сумму из баланса
                        if operation.operation_type == 'sale' and operation.status == 'confirmed':
                            user.balance -= operation.amount
                        db.session.delete(operation)
                db.session.commit()
            else:
                flash('Не выбрано ни одного ключа для удаления', 'warning')
        return redirect(url_for('manage_keys', user_id=user_id))

    # Получение всех ключей из вторичной базы данных
    conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
    cursor = conn.cursor()
    all_keys = [
        {
            'key': row[0],
            'status': row[1],
            'start_date': row[2],
            'end_date': row[3],
            'tariff_id': row[4],
        }
        for row in cursor.execute("""
            SELECT key, status, start_date, end_date, tariff_id 
            FROM user_keys
        """)
    ]
    conn.close()

    # Получение ключей, которые уже привязаны к пользователям
    assigned_keys = UserKey.query.with_entities(UserKey.key).all()
    assigned_key_values = set([key[0] for key in assigned_keys])  # Извлекаем значения ключей

    # Доступные ключи - это все ключи, не привязанные к пользователям
    available_keys = [key for key in all_keys if key['key'] not in assigned_key_values]

    # Получение ключей, привязанных к текущему пользователю, с операциями
    user_keys = UserKey.query.filter_by(user_id=user_id).all()
    processed_user_keys = []
    for key in user_keys:
        days_left = 'N/A'
        if key.end_date:
            try:
                days_left = (datetime.strptime(key.end_date, '%Y-%m-%d %H:%M:%S') - datetime.now()).days
            except ValueError:
                days_left = 'Ошибка в формате даты'

        # Получение соответствующей операции
        operation = UserOperation.query.filter_by(user_id=user_id, product_id=key.id).first()
        if operation:
            operation_data = {
                'operation_id': operation.id,
                'operation_type': operation.operation_type,
                'amount': operation.amount,
                'status': operation.status,
                'date': operation.date.strftime('%Y-%m-%d %H:%M:%S')
            }
        else:
            operation_data = {
                'operation_id': None,
                'operation_type': '',
                'amount': '',
                'status': '',
                'date': ''
            }

        processed_user_keys.append({
            'id': key.id,  # Добавляем ID ключа
            'key': key.key,
            'status': key.status,
            'start_date': key.start_date,
            'end_date': key.end_date,
            'days_left': days_left,
            'tariff_id': key.tariff_id,
            'operation': operation_data
        })


    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Управление ключами</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <style>
            .container { max-width: 1200px; margin-top: 50px; }
            .btn-group { display: flex; gap: 10px; margin-bottom: 20px; }
            .table-container { margin-top: 20px; }
            table { width: 100%; margin-top: 20px; border-collapse: collapse; }
            th, td { padding: 8px; border: 1px solid #ddd; text-align: left; }
            th { background-color: #f2f2f2; position: relative; }
            .editable { cursor: pointer; color: blue; text-decoration: underline; } /* Визуальное оформление */
            .modal { display: none; position: fixed; z-index: 100; left: 0; top: 0; width: 100%; height: 100%; overflow: auto;
                     background-color: rgba(0,0,0,0.4); }
            .modal-content { background-color: #fefefe; margin: 2% auto; padding: 20px; border: 1px solid #888;
                             width: 90%; max-width: 1200px; height: 80%; max-height: 90vh; overflow-y: auto; }
            .close { float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
            .filter-input { margin-top: 10px; width: 100%; }
            .alert { padding: 10px; margin-top: 10px; }
            #addKeySelect, #detachKeySelect { width: 100%; height: 400px; box-sizing: border-box; }
            .dropdown-item { cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Управление ключами для пользователя {{ user.username }}</h1>
            <a href="{{ url_for('user_summary', user_id=user.id) }}" class="btn btn-secondary mb-3">Назад к профилю пользователя</a>


            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    <div class="alert-container">
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    </div>
                {% endif %}
            {% endwith %}

            <div class="btn-group">
                <button id="openAddKeyModal" class="btn btn-primary">Добавить существующий ключ</button>
                <button id="openManualKeyModal" class="btn btn-info">Добавить вручную</button>
                <button id="openDetachKeyModal" class="btn btn-danger" >Удалить ключ</button>
            </div>

            <div class="table-container">
                <table id="keyTable" class="table">
                    <thead>
                        <tr>
                            <th>Ключ</th>
                            <th>Статус</th>
                            <th>Дата начала</th>
                            <th>Дата окончания</th>
                            <th>Осталось дней</th>
                            <th>Тип операции</th>
                            <th>Сумма</th>
                            <th>Статус операции</th>
                            <th>Дата операции</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for key in processed_user_keys %}
                        <tr>
                            <td>{{ key.key }}</td>
                            <td>{{ key.status }}</td>
                            <td>{{ key.start_date }}</td>
                            <td>{{ key.end_date }}</td>
                            <td>{{ key.days_left }}</td>
                            <td class="editable" data-operation-id="{{ key.operation.operation_id }}" data-field-name="operation_type" data-key-id="{{ key.id }}">
                                {% if key.operation.operation_type == 'sale' %}Продажа{% elif key.operation.operation_type == 'consignment' %}Реализация{% else %}{{ key.operation.operation_type }}{% endif %}
                            </td>
                            <td class="editable" data-operation-id="{{ key.operation.operation_id }}" data-field-name="amount" data-key-id="{{ key.id }}">{{ key.operation.amount }}</td>
                            <td class="editable" data-operation-id="{{ key.operation.operation_id }}" data-field-name="status" data-key-id="{{ key.id }}">
                                {% if key.operation.status == 'pending' %}В ожидании{% elif key.operation.status == 'confirmed' %}Подтверждено{% elif key.operation.status == 'cancelled' %}Отменено{% else %}{{ key.operation.status }}{% endif %}
                            </td>
                            <td>{{ key.operation.date }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

            <!-- Модальное окно для добавления существующего ключа -->
            <div id="addKeyModal" class="modal">
                <div class="modal-content">
                    <span class="close" id="closeAddKeyModal">&times;</span>
                    <h3>Добавить существующий ключ</h3>
                    <input type="text" id="addKeySearch" class="filter-input" placeholder="Поиск по ключу...">
                    <form method="POST">
                        <input type="hidden" name="action" value="add_keys">
                        <div class="form-group">
                            <label for="new_keys">Выберите ключи</label>
                            <select id="addKeySelect" name="new_keys" class="form-control" multiple></select>
                        </div>
                        <div class="form-group">
                            <label for="operation_type">Тип операции</label>
                            <select name="operation_type" class="form-control">
                                <option value="sale">Продажа</option>
                                <option value="consignment">Реализация</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="amount">Сумма</label>
                            <input type="number" name="amount" class="form-control" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Добавить ключи</button>
                    </form>
                </div>
            </div>

            <!-- Модальное окно для добавления ключа вручную -->
            <div id="manualKeyModal" class="modal">
                <div class="modal-content">
                    <span class="close" id="closeManualKeyModal">&times;</span>
                    <h3>Добавить ключ вручную</h3>
                    <form method="POST">
                        <input type="hidden" name="action" value="add_manual_key">
                        <div class="form-group">
                            <label for="manual_key">Введите ключ</label>
                            <input type="text" name="manual_key" class="form-control" required>
                        </div>
                        <button type="submit" class="btn btn-info">Добавить вручную</button>
                    </form>
                </div>
            </div>

            <!-- Модальное окно для удаления ключа -->
            <div id="detachKeyModal" class="modal">
                <div class="modal-content">
                    <span class="close" id="closeDetachKeyModal">&times;</span>
                    <h3>Удалить ключ</h3>
                    <input type="text" id="detachKeySearch" class="filter-input" placeholder="Поиск по ключу...">
                    <form method="POST">
                        <input type="hidden" name="action" value="detach_keys">
                        <div class="form-group">
                            <label for="detach_keys">Выберите ключи для удаления</label>
                            <select id="detachKeySelect" name="detach_keys" class="form-control" multiple></select>
                        </div>
                        <button type="submit" class="btn btn-danger">Удалить ключи</button>
                    </form>
                </div>
            </div>

            <script>
                const availableKeys = {{ available_keys | tojson }};
                const userKeys = {{ processed_user_keys | tojson }};

                function populateOptions(selectElement, optionsData, filter = "") {
                    const filteredKeys = optionsData.filter(key => 
                        key.key.toLowerCase().includes(filter.toLowerCase())
                    );

                    selectElement.innerHTML = ""; // Очистка списка
                    filteredKeys.forEach(key => {
                        const option = document.createElement("option");
                        option.value = key.key;
                        option.text = `${key.key} (Статус: ${key.status}, Начало: ${key.start_date}, Конец: ${key.end_date})`;
                        selectElement.appendChild(option);
                    });
                }

                $(document).ready(function() {
                    $("#openAddKeyModal").click(function() {
                        $("#addKeyModal").css("display", "block");
                        populateOptions(document.getElementById("addKeySelect"), availableKeys); 
                    });
                    $("#closeAddKeyModal").click(function() {
                        $("#addKeyModal").css("display", "none");
                    });

                    $("#openManualKeyModal").click(function() {
                        $("#manualKeyModal").css("display", "block");
                    });
                    $("#closeManualKeyModal").click(function() {
                        $("#manualKeyModal").css("display", "none");
                    });

                    $("#openDetachKeyModal").click(function() {
                        $("#detachKeyModal").css("display", "block");
                        populateOptions(document.getElementById("detachKeySelect"), userKeys); 
                    });
                    $("#closeDetachKeyModal").click(function() {
                        $("#detachKeyModal").css("display", "none");
                    });

                    $("#addKeySearch").on("input", function() {
                        const filter = $(this).val();
                        populateOptions(document.getElementById("addKeySelect"), availableKeys, filter);
                    });

                    $("#detachKeySearch").on("input", function() {
                        const filter = $(this).val();
                        populateOptions(document.getElementById("detachKeySelect"), userKeys, filter);
                    });

                    // Обработка редактирования ячеек
                    $('.editable').click(function() {
                        let currentElement = $(this);
                        let originalValue = currentElement.text().trim();
                        let fieldName = currentElement.data('field-name');
                        let operationId = currentElement.data('operation-id');
                        let keyId = currentElement.data('key-id'); // Получаем ID ключа

                        let inputElement;

                        if (fieldName === 'operation_type' || fieldName === 'status' || fieldName === 'amount') {
                            // Handling operation fields
                            if (!operationId) {
                                // Create new operation
                                operationId = 'new';
                            }

                            if (fieldName === 'operation_type' || fieldName === 'status') {
                                let options = fieldName === 'operation_type' ?
                                    {'sale': 'Продажа', 'consignment': 'Реализация'} :
                                    {'pending': 'В ожидании', 'confirmed': 'Подтверждено', 'cancelled': 'Отменено'};

                                inputElement = $('<select class="form-control"></select>');
                                $.each(options, function(value, text) {
                                    inputElement.append($('<option></option>').attr('value', value).text(text));
                                });
                                // Устанавливаем значение по умолчанию
                                inputElement.val(Object.keys(options).find(key => options[key] === originalValue));
                            } else {
                                inputElement = $('<input type="text" class="form-control" />').val(originalValue);
                            }

                            currentElement.html(inputElement);
                            inputElement.focus();

                            inputElement.blur(function() {
                                let newValue = $(this).val();

                                $.ajax({
                                    url: "{{ url_for('update_operation_field') }}",
                                    type: 'POST',
                                    data: {
                                        operation_id: operationId,
                                        field_name: fieldName,
                                        new_value: newValue,
                                        user_id: {{ user.id }},
                                        key_id: keyId
                                    },
                                    success: function(response) {
                                        if (response.success) {
                                            if (fieldName === 'operation_type') {
                                                let displayValue = {'sale': 'Продажа', 'consignment': 'Реализация'}[newValue] || newValue;
                                                currentElement.text(displayValue);
                                            } else if (fieldName === 'status') {
                                                let displayValue = {'pending': 'В ожидании', 'confirmed': 'Подтверждено', 'cancelled': 'Отменено'}[newValue] || newValue;
                                                currentElement.text(displayValue);
                                            } else {
                                                currentElement.text(newValue);
                                            }
                                            // Обновляем operation_id, если операция была создана
                                            if (response.operation_id) {
                                                currentElement.data('operation-id', response.operation_id);
                                            }
                                        } else {
                                            alert('Ошибка: ' + response.message);
                                            currentElement.text(originalValue);
                                        }
                                    },
                                    error: function() {
                                        alert('Ошибка при отправке запроса.');
                                        currentElement.text(originalValue);
                                    }
                                });
                            });
                        }
                    });
                });
            </script>
        </div>
    </body>
    </html>
    ''', user=user, available_keys=available_keys, processed_user_keys=processed_user_keys)



# Маршрут для обновления полей операции через AJAX
@app.route('/update_operation_field', methods=['POST'])
@auth_required
@role_required('admin')
def update_operation_field():
    operation_id = request.form.get('operation_id')
    field_name = request.form.get('field_name')
    new_value = request.form.get('new_value')
    user_id = int(request.form.get('user_id'))
    key_id = int(request.form.get('key_id'))

    operation = None

    if operation_id == 'new':
        # Проверяем, существует ли операция для данной пары user_id и key_id
        operation = UserOperation.query.filter_by(user_id=user_id, product_id=key_id).first()
        if not operation:
            # Создаем новую операцию
            operation = UserOperation(
                user_id=user_id,
                operation_type='',
                product_id=key_id,
                amount=0.0,
                status='pending',
                date=datetime.utcnow()
            )
            db.session.add(operation)
            db.session.commit()
            operation_id = operation.id
    else:
        operation = UserOperation.query.get(operation_id)
        if not operation:
            return jsonify({'success': False, 'message': 'Операция не найдена'})

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'})

    # Сохраняем старые значения для корректировки баланса
    old_amount = operation.amount
    old_operation_type = operation.operation_type
    old_status = operation.status

    # Обновляем поле операции на основе переданных данных
    if field_name == 'operation_type':
        if new_value not in ['sale', 'consignment', 'manual_add', 'return']:
            return jsonify({'success': False, 'message': 'Некорректный тип операции'})
        operation.operation_type = new_value
    elif field_name == 'amount':
        try:
            operation.amount = float(new_value)
        except ValueError:
            return jsonify({'success': False, 'message': 'Некорректная сумма'})
    elif field_name == 'status':
        if new_value not in ['pending', 'confirmed', 'cancelled']:
            return jsonify({'success': False, 'message': 'Некорректный статус'})
        operation.status = new_value
    else:
        return jsonify({'success': False, 'message': 'Некорректное поле'})

    # Корректировка баланса пользователя

    # Убираем старую сумму, если старая операция была подтвержденной продажей или реализацией
    if old_status == 'confirmed' and old_operation_type in ['sale', 'consignment']:
        user.balance -= old_amount

    # Добавляем новую сумму, если новая операция подтверждена и имеет тип 'sale' или 'consignment'
    if operation.status == 'confirmed' and operation.operation_type in ['sale', 'consignment']:
        user.balance += operation.amount
    elif operation.status == 'confirmed' and operation.operation_type == 'return':
        # Возврат товара: уменьшение баланса
        user.balance -= operation.amount

    db.session.commit()
    return jsonify({'success': True, 'operation_id': operation_id})






# Дополнительная функция для добавления операции
def add_operation(user_id, operation_type, product_id, amount):
    """
    Добавляет новую операцию для пользователя и обновляет баланс при необходимости.
    Если операция для данного пользователя и продукта уже существует, обновляет ее.
    """
    operation = UserOperation.query.filter_by(user_id=user_id, product_id=product_id).first()
    if not operation:
        operation = UserOperation(
            user_id=user_id,
            operation_type=operation_type,
            product_id=product_id,
            amount=amount,
            status='pending' if operation_type == 'consignment' else 'confirmed',
            date=datetime.utcnow()
        )
        db.session.add(operation)
    else:
        # Обновляем существующую операцию
        operation.operation_type = operation_type
        operation.amount = amount
        operation.status = 'pending' if operation_type == 'consignment' else 'confirmed'
        operation.date = datetime.utcnow()

    # Обновление баланса только при подтвержденных продажах
    if operation_type == 'sale':
        user = User.query.get(user_id)
        user.balance += amount
    db.session.commit()



# Функции для работы с ключами
def add_keys(user_id, keys):
    # Проверка, чтобы исключить добавление уже привязанных к другому пользователю ключей
    existing_keys = {key.key for key in UserKey.query.all()}  # Собираем все привязанные ключи
    new_keys = [key for key in keys if key not in existing_keys]

    if new_keys:
        # Подключение к вторичной базе данных
        with sqlite3.connect(SECONDARY_DATABASE_PATH) as conn:
            cursor = conn.cursor()
            for key in new_keys:
                # Получаем данные ключа из вторичной базы данных
                cursor.execute("SELECT status, start_date, end_date, tariff_id FROM user_keys WHERE key=?", (key,))
                result = cursor.fetchone()
                if result:
                    # Создаем объект UserKey с данными ключа
                    user_key = UserKey(
                        user_id=user_id,
                        key=key,
                        status=result[0],
                        start_date=result[1],
                        end_date=result[2],
                        tariff_id=result[3]
                    )
                    # Добавляем объект в сессию базы данных
                    db.session.add(user_key)
        
        # Коммитим изменения в основной базе данных
        db.session.commit()
        flash('Ключи успешно добавлены', 'success')
    else:
        flash('Выбранные ключи уже привязаны к пользователю', 'warning')


def add_manual_key(user_id, manual_key):
    # Проверка на уже существующую привязку ключа к другому пользователю
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
                status=result[0],
                start_date=result[1],
                end_date=result[2],
                tariff_id=result[3]
            )
            db.session.add(user_key)
        conn.close()
        db.session.commit()
        flash('Ключ успешно добавлен вручную', 'success')

def detach_keys(user_id, keys):
    if keys:
        for key in keys:
            UserKey.query.filter_by(user_id=user_id, key=key).delete()
        db.session.commit()
        flash('Ключи успешно отвязаны', 'success')
    else:
        flash('Не выбрано ни одного ключа для удаления', 'warning')
        

@app.route('/asic-functions', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def asic_functions_page():
    message = ''
    try:
        conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Обработка POST-запросов по типу формы
        if request.method == 'POST':
            form_type = request.form.get('form_type')
            if form_type == 'add_mapping':
                # Добавление связи: выбираем модель и функциональность из выпадающих списков
                model_id = request.form.get('model_id')
                functionality_id = request.form.get('functionality_id')
                try:
                    state = int(request.form.get('state', 0))
                except ValueError:
                    state = 0
                if not model_id or not functionality_id:
                    message = 'Выберите модель и функциональность.'
                else:
                    # Проверяем, существует ли уже такая связь
                    cursor.execute("""
                        SELECT id FROM model_functionalities 
                        WHERE asic_model_id = ? AND functionality_id = ?
                    """, (model_id, functionality_id))
                    if cursor.fetchone():
                        message = 'Такая связь уже существует.'
                    else:
                        cursor.execute("""
                            INSERT INTO model_functionalities (asic_model_id, functionality_id, state)
                            VALUES (?, ?, ?)
                        """, (model_id, functionality_id, state))
                        conn.commit()
                        message = 'Связь успешно добавлена.'
            elif form_type == 'delete_mapping':
                # Удаление связи из model_functionalities
                record_id = request.form.get('record_id')
                if record_id:
                    cursor.execute("DELETE FROM model_functionalities WHERE id = ?", (record_id,))
                    conn.commit()
                    message = 'Связь успешно удалена.'
            elif form_type == 'add_model':
                # Добавление новой модели
                asic_model = request.form.get('new_model')
                if not asic_model:
                    message = 'Укажите название модели.'
                else:
                    try:
                        cursor.execute("INSERT INTO asic_models (name) VALUES (?)", (asic_model,))
                        conn.commit()
                        message = 'Модель успешно добавлена.'
                    except sqlite3.IntegrityError:
                        message = 'Такая модель уже существует.'
            elif form_type == 'delete_model':
                # Удаление модели: сначала удаляем связи, затем модель
                model_id = request.form.get('model_id')
                if model_id:
                    cursor.execute("DELETE FROM model_functionalities WHERE asic_model_id = ?", (model_id,))
                    cursor.execute("DELETE FROM asic_models WHERE id = ?", (model_id,))
                    conn.commit()
                    message = 'Модель успешно удалена.'
            elif form_type == 'add_functionality':
                # Добавление новой функциональности
                functionality = request.form.get('new_functionality')
                if not functionality:
                    message = 'Укажите название функциональности.'
                else:
                    try:
                        cursor.execute("INSERT INTO functionalities (name) VALUES (?)", (functionality,))
                        conn.commit()
                        message = 'Функциональность успешно добавлена.'
                    except sqlite3.IntegrityError:
                        message = 'Такая функциональность уже существует.'
            elif form_type == 'delete_functionality':
                # Удаление функциональности: сначала удаляем связи, затем функциональность
                functionality_id = request.form.get('functionality_id')
                if functionality_id:
                    cursor.execute("DELETE FROM model_functionalities WHERE functionality_id = ?", (functionality_id,))
                    cursor.execute("DELETE FROM functionalities WHERE id = ?", (functionality_id,))
                    conn.commit()
                    message = 'Функциональность успешно удалена.'

        # Получение списка связей (mapping) с объединением таблиц
        cursor.execute("""
            SELECT mf.id, am.name AS asic_model, f.name AS functionality, mf.state
            FROM model_functionalities mf
            JOIN asic_models am ON mf.asic_model_id = am.id
            JOIN functionalities f ON mf.functionality_id = f.id
        """)
        mapping_records = cursor.fetchall()
        mapping_list = []
        for rec in mapping_records:
            display_state = "Включена" if rec['state'] == 1 else "Выключена"
            mapping_list.append({
                'id': rec['id'],
                'asic_model': rec['asic_model'],
                'functionality': rec['functionality'],
                'state': display_state
            })
        
        # Получение всех моделей
        cursor.execute("SELECT id, name FROM asic_models")
        models = cursor.fetchall()
        
        # Получение всех функциональных возможностей
        cursor.execute("SELECT id, name FROM functionalities")
        functionalities = cursor.fetchall()
        
        conn.close()
    except Exception as e:
        return f"Ошибка доступа к базе данных: {e}", 500
    
    # HTML-шаблон для страницы управления ASIC настройками
    template = '''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Управление ASIC настройками</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .container { margin-top: 20px; }
            table { width: 100%; }
            th, td { padding: 8px; text-align: center; }
            .message { margin-top: 10px; }
            .section { margin-bottom: 40px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Управление ASIC настройками</h1>
            {% if message %}
                <div class="alert alert-info">{{ message }}</div>
            {% endif %}
            
            <!-- Управление моделями -->
            <div class="section">
                <h2>Модели ASIC</h2>
                <form method="POST" class="mb-3">
                    <input type="hidden" name="form_type" value="add_model">
                    <div class="form-group">
                        <label for="new_model">Добавить новую модель</label>
                        <input type="text" class="form-control" name="new_model" id="new_model" placeholder="Например, Antminer S19" required>
                    </div>
                    <button type="submit" class="btn btn-success">Добавить модель</button>
                </form>
                <table class="table table-bordered">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Модель</th>
                            <th>Действие</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for model in models %}
                        <tr>
                            <td>{{ model['id'] }}</td>
                            <td>{{ model['name'] }}</td>
                            <td>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="form_type" value="delete_model">
                                    <input type="hidden" name="model_id" value="{{ model['id'] }}">
                                    <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Удалить модель?');">Удалить</button>
                                </form>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            <!-- Управление функциональностями -->
            <div class="section">
                <h2>Функциональности</h2>
                <form method="POST" class="mb-3">
                    <input type="hidden" name="form_type" value="add_functionality">
                    <div class="form-group">
                        <label for="new_functionality">Добавить новую функциональность</label>
                        <input type="text" class="form-control" name="new_functionality" id="new_functionality" placeholder="Например, перезагрузка" required>
                    </div>
                    <button type="submit" class="btn btn-success">Добавить функциональность</button>
                </form>
                <table class="table table-bordered">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Функциональность</th>
                            <th>Действие</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for func in functionalities %}
                        <tr>
                            <td>{{ func['id'] }}</td>
                            <td>{{ func['name'] }}</td>
                            <td>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="form_type" value="delete_functionality">
                                    <input type="hidden" name="functionality_id" value="{{ func['id'] }}">
                                    <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Удалить функциональность?');">Удалить</button>
                                </form>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            <!-- Добавление связи модели и функциональности -->
            <div class="section">
                <h2>Добавить связь модели и функциональности</h2>
                <form method="POST" class="mb-4">
                    <input type="hidden" name="form_type" value="add_mapping">
                    <div class="form-group">
                        <label for="model_id">Модель асика</label>
                        <select class="form-control" name="model_id" id="model_id" required>
                            <option value="">Выберите модель</option>
                            {% for model in models %}
                            <option value="{{ model['id'] }}">{{ model['name'] }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="functionality_id">Функциональность</label>
                        <select class="form-control" name="functionality_id" id="functionality_id" required>
                            <option value="">Выберите функциональность</option>
                            {% for func in functionalities %}
                            <option value="{{ func['id'] }}">{{ func['name'] }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="state">Состояние</label>
                        <select class="form-control" name="state" id="state">
                            <option value="1">Включена</option>
                            <option value="0" selected>Выключена</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-success">Добавить связь</button>
                </form>
            </div>
            
            <!-- Список связей -->
            <div class="section">
                <h2>Список связей моделей и функциональностей</h2>
                <table class="table table-bordered">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Модель асика</th>
                            <th>Функциональность</th>
                            <th>Состояние</th>
                            <th>Действие</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for record in mapping_list %}
                        <tr>
                            <td>{{ record['id'] }}</td>
                            <td>{{ record['asic_model'] }}</td>
                            <td>{{ record['functionality'] }}</td>
                            <td>{{ record['state'] }}</td>
                            <td>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="form_type" value="delete_mapping">
                                    <input type="hidden" name="record_id" value="{{ record['id'] }}">
                                    <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Удалить связь?');">Удалить</button>
                                </form>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, models=models, functionalities=functionalities, mapping_list=mapping_list, message=message)


@app.route('/devices', methods=['GET'])
@auth_required
@role_required('admin')
def devices_list():
    devices_db_path = '/root/websocket/devices_data.db'
    
    try:
        conn = sqlite3.connect(devices_db_path)
        cursor = conn.cursor()

        # Выполнить запрос для получения всех устройств
        cursor.execute("SELECT * FROM device_data")
        devices = cursor.fetchall()

        # Формат данных для таблицы
        devices_info = []
        
        for index, device in enumerate(devices, start=1):
            structured_data = None
            try:
                structured_data = json.loads(device[4])
            except (json.JSONDecodeError, TypeError):
                pass
            
            devices_info.append({
                'number': index,
                'uid': device[1],
                'ip': device[2],
                'port': device[3],
                'internal_ip': structured_data.get('internal_ip') if structured_data else None,
                'data': structured_data,
                'timestamp': structured_data.get('current_time') if structured_data and 'current_time' in structured_data else '',
                'status': 'Online' if structured_data else 'Offline',
                'distro_name': structured_data.get('distro_name') if structured_data else '',
                'distro_release': structured_data.get('distro_release') if structured_data else '',
                'kernel_version': structured_data.get('kernel_version') if structured_data else ''
            })

        conn.close()

    except Exception as e:
        return f"Error accessing device database: {e}", 500

    # HTML-шаблон для отображения списка устройств
    template = '''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Список устройств</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .table-container {
                display: flex;
                justify-content: center;
                align-items: center;
                flex-direction: column;
            }
            table {
                width: auto;
                table-layout: auto;
            }
            th, td {
                white-space: nowrap;
                padding: 8px;
                text-align: left;
            }
        </style>
    </head>
    <body>
        <div class="container table-container">
            <h1>Список устройств</h1>
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>№</th>
                        <th>UID</th>
                        <th>IP</th>
                        <th>Внутренний IP</th>
                        <th>Порт</th>
                        <th>Время</th>
                        <th>Статус</th>
                        <th>Название ОС</th>
                        <th>Релиз ОС</th>
                        <th>Версия ядра</th>
                        <th>Действие</th>
                    </tr>
                </thead>
                <tbody>
                    {% for device in devices_info %}
                    <tr>
                        <td>{{ device['number'] }}</td>
                        <td>{{ device['uid'] }}</td>
                        <td>{{ device['ip'] }}</td>
                        <td>{{ device['internal_ip'] or 'N/A' }}</td>
                        <td>{{ device['port'] }}</td>
                        <td>{{ device['timestamp'] }}</td>
                        <td>
                            <span class="badge badge-{{ 'success' if device['status'] == 'Online' else 'danger' }}">
                                {{ device['status'] }}
                            </span>
                        </td>
                        <td>{{ device['distro_name'] }}</td>
                        <td>{{ device['distro_release'] }}</td>
                        <td>{{ device['kernel_version'] }}</td>
                        <td>
                            <a href="/key_access/{{ device['uid'] }}" class="btn btn-primary btn-sm">Посмотреть</a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    '''

    return render_template_string(template, devices_info=devices_info)



def get_device_data_by_uid(key):
    """
    Считывает запись из /root/websocket/devices_data.db по uid=key.
    Возвращает (device_info, structured_data) или (None, None).
    """
    devices_db_path = '/root/websocket/devices_data.db'
    try:
        conn = sqlite3.connect(devices_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM device_data WHERE uid = ?", (key,))
        device_data = cursor.fetchone()
        conn.close()
    except Exception:
        return None, None

    if device_data:
        device_info = {
            'id': device_data[0],
            'uid': device_data[1],
            'ip': device_data[2],
            'port': device_data[3],
            'data': device_data[4],
            'timestamp': device_data[5]
        }
        # Парсим JSON из поля 'data'
        try:
            structured_data = json.loads(device_info['data'])
        except (json.JSONDecodeError, TypeError):
            structured_data = None
        return device_info, structured_data
    else:
        return None, None

def get_secondary_data_for_key(key):
    """
    Извлекает из второй БД (SECONDARY_DATABASE_PATH) все записи, где key = ?.
    Предполагаем, что таблица называется 'miner_data'
    и в ней есть поля: key, miner_ip, pool_user.

    Возвращает список словарей:
      [
        {"miner_ip": "...", "pool_user": "..."},
        ...
      ]
    """
    results = []
    try:
        conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
        cursor = conn.cursor()
        query = "SELECT miner_ip, pool_user FROM miner_data WHERE key = ?"
        cursor.execute(query, (key,))
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            miner_ip, pool_user = row
            results.append({"miner_ip": miner_ip, "pool_user": pool_user})
    except Exception:
        pass

    return results

@app.route('/key_access/<key>', methods=['GET'])
@auth_required
@role_required('admin')
def key_access(key):
    # 1) Основная база (device_data)
    device_info, structured_data = get_device_data_by_uid(key)

    # 2) Вторая база (miner_data)
    secondary_data = get_secondary_data_for_key(key)
    secondary_total = len(secondary_data)

    # Список оффлайн-IP (если "offline" в pool_user)
    offline_ips = [
        item["miner_ip"] 
        for item in secondary_data 
        if "offline" in item.get("pool_user", "").lower()
    ]
    offline_count = len(offline_ips)

    # Собираем IP из второй базы
    secondary_ips = set(item["miner_ip"] for item in secondary_data)

    # Собираем IP устройства (из structured_data, если есть miner_info)
    device_ip_count = 0
    device_ips = set()
    if structured_data and "miner_info" in structured_data:
        device_ip_count = structured_data["miner_info"].get("ip_count", 0)
        ip_data = structured_data["miner_info"].get("ip_data", {})
        device_ips = set(ip_data.keys())

    # Находим IP, которые не совпадают
    missing_on_client = secondary_ips - device_ips  # есть на сервере, нет на устройстве
    missing_on_server = device_ips - secondary_ips  # есть на устройстве, нет на сервере

    # Предыдущий URL
    previous_url = request.referrer if request.referrer else '/keys_management_view'

    # Вычисляем "time_ago"
    time_ago = None
    if device_info:
        try:
            timestamp_format = "%Y-%m-%d %H:%M:%S"
            utc = pytz.utc
            timestamp = datetime.strptime(device_info['timestamp'], timestamp_format)
            timestamp = utc.localize(timestamp)

            local_timezone = pytz.timezone("Europe/Moscow")  # замените по необходимости
            current_time = datetime.now(utc).astimezone(local_timezone)
            timestamp_local = timestamp.astimezone(local_timezone)
            time_difference = current_time - timestamp_local

            seconds = time_difference.total_seconds()
            if seconds < 60:
                time_ago = f"{int(seconds)} секунд назад"
            elif seconds < 3600:
                minutes = int(seconds // 60)
                time_ago = f"{minutes} минут назад"
            else:
                hours = int(seconds // 3600)
                time_ago = f"{hours} часов назад"
        except:
            pass

    # HTML-шаблон
    template = '''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <title>Детали ключа {{ device_info['uid'] if device_info else '' }}</title>
        <!-- Подключаем только CSS Bootstrap для красивых таблиц/кнопок -->
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .table-container {
                display: flex;
                justify-content: center;
                align-items: center;
                flex-direction: column;
            }
            table {
                width: auto;
                table-layout: auto;
            }
            th, td {
                white-space: nowrap;
                padding: 8px;
                text-align: left;
            }
            /* Скрываем по умолчанию список OFFLINE IP */
            #offlineList {
                display: none;
            }
        </style>
    </head>
    <body>
        <div class="container table-container">
            <h1>Информация о ключе: {{ device_info['uid'] if device_info else '' }}</h1>

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
                    <td>{{ device_info['timestamp'] }}{% if time_ago %} ({{ time_ago }}){% endif %}</td>
                </tr>
            </table>

            {% if structured_data %}
            <h3>Основная информация</h3>
            <table class="table table-bordered">
                <tr>
                    <th>CPU Load</th>
                    <td>{{ structured_data.get('cpu_load', '') }}</td>
                </tr>
                <tr>
                    <th>Использование памяти</th>
                    <td>{{ structured_data.get('memory_usage', '') }}</td>
                </tr>
                <tr>
                    <th>Использование диска</th>
                    <td>{{ structured_data.get('disk_usage', '') }}</td>
                </tr>
                <tr>
                    <th>Внутренний IP</th>
                    <td>{{ structured_data.get('internal_ip', '') }}</td>
                </tr>
                <tr>
                    <th>Версия клиента</th>
                    <td>{{ structured_data.get('client_version', '') }}</td>
                </tr>
                <tr>
                    <th>Статус</th>
                    <td>{{ structured_data.get('status', '') }}</td>
                </tr>
                <tr>
                    <th>Название ОС</th>
                    <td>{{ structured_data.get('distro_name', '') }}</td>
                </tr>
                <tr>
                    <th>Релиз ОС</th>
                    <td>{{ structured_data.get('distro_release', '') }}</td>
                </tr>
                <tr>
                    <th>Версия ядра</th>
                    <td>{{ structured_data.get('kernel_version', '') }}</td>
                </tr>
                <tr>
                    <th>Время с устройства</th>
                    <td>{{ structured_data.get('current_time', '') }}</td>
                </tr>
                <!-- Если убираем "Основной туннель (22222)", удаляем этот блок -->
                <!-- Вместо этого, если нужен только один туннель (22333), оставляем строку ниже -->
                <tr>
                    <th>Туннель (22333)</th>
                    <td>
                        {% if structured_data.get('tunnel_22333_running') %}
                            Запущен
                        {% else %}
                            Остановлен
                        {% endif %}
                    </td>
                </tr>
            </table>

            <h3>Процессы</h3>
            {% if 'process_info' in structured_data %}
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>PID</th>
                        <th>CPU</th>
                        <th>Memory</th>
                        <th>Command Line</th>
                    </tr>
                </thead>
                <tbody>
                    {% for process in structured_data['process_info'] %}
                    <tr>
                        <td>{{ process.get('pid', '') }}</td>
                        <td>{{ process.get('cpu_usage', '') }}</td>
                        <td>{{ process.get('memory_usage', '') }}</td>
                        <td>{{ process.get('command_line', '') }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
                <p>Нет данных о процессах.</p>
            {% endif %}

            <h3>Диагностика</h3>
            {% if 'miner_info' in structured_data %}
                <p>Найдено IP (устройство): {{ device_ip_count }}</p>
                <!-- Кнопка перехода на детальный просмотр диагностики (если есть соответствующий роут) -->
                <a href="{{ url_for('key_access_diagnostics', key=device_info['uid']) }}" class="btn btn-info">
                    Просмотр диагностики
                </a>
            {% else %}
                <p>Нет данных по майнерам (устройство).</p>
            {% endif %}

            <h3>Серверная База</h3>
            <p>Всего IP: {{ secondary_total }}</p>
            <p>
                Оффлайн: {{ offline_count }}
                <button class="btn btn-secondary btn-sm" id="showOfflineBtn">
                    Показать OFFLINE IP
                </button>
            </p>
            <div id="offlineList" class="mb-3">
                <ul>
                  {% for ip in offline_ips %}
                  <li>{{ ip }}</li>
                  {% endfor %}
                </ul>
            </div>

            <h4>Несоответствующие IP</h4>
            <p>Есть на сервере, нет на устройстве: {{ missing_on_client|length }}</p>
            {% if missing_on_client %}
            <ul>
            {% for ip in missing_on_client %}
                <li>{{ ip }}</li>
            {% endfor %}
            </ul>
            {% endif %}

            <p>Есть на устройстве, нет на сервере: {{ missing_on_server|length }}</p>
            {% if missing_on_server %}
            <ul>
            {% for ip in missing_on_server %}
                <li>{{ ip }}</li>
            {% endfor %}
            </ul>
            {% endif %}

            {% else %}
                <p>Нет структурированных данных.</p>
            {% endif %}

            {% else %}
                <p>Данные по ключу не найдены.</p>
            {% endif %}

            <a href="{{ previous_url }}" class="btn btn-primary">Назад</a>
        </div>

        <!-- Простой JS: показываем/скрываем список OFFLINE IP без Bootstrap JS/jQuery -->
        <script>
        document.addEventListener("DOMContentLoaded", function() {
            var btn = document.getElementById("showOfflineBtn");
            var list = document.getElementById("offlineList");
            if(btn) {
                btn.addEventListener("click", function(){
                    if (list.style.display === "none") {
                        list.style.display = "block";
                    } else {
                        list.style.display = "none";
                    }
                });
            }
        });
        </script>
    </body>
    </html>
    '''

    return render_template_string(
        template,
        device_info=device_info,
        structured_data=structured_data,
        previous_url=previous_url,
        time_ago=time_ago,
        secondary_total=secondary_total,
        offline_count=offline_count,
        offline_ips=offline_ips,
        device_ip_count=device_ip_count,
        missing_on_client=missing_on_client,
        missing_on_server=missing_on_server
    )




@app.route('/key_access/<key>/diagnostics', methods=['GET'])
@auth_required
@role_required('admin')
def key_access_diagnostics(key):
    device_info, structured_data = get_device_data_by_uid(key)

    previous_url = request.referrer if request.referrer else '/key_access/{}'.format(key)

    template = '''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <title>Диагностика {{ device_info['uid'] if device_info else '' }}</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            /* Контейнер для таблиц */
            .table-container {
                display: flex;
                flex-direction: column;
                align-items: flex-start;
                width: 100%;
            }
            /* Таблица на всю ширину, фиксированная вёрстка */
            table {
                width: 100%;
                table-layout: fixed;
            }
            /* Убираем nowrap, включаем перенос слов */
            th, td {
                padding: 8px;
                text-align: left;
                word-wrap: break-word;
                white-space: pre-wrap; 
            }
            /* Для блоков с многострочным текстом (вместо <pre>) */
            .code-block {
                margin: 0;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
        </style>
    </head>
    <body>
        <div class="container table-container">
            <h1>Диагностика для ключа: {{ device_info['uid'] if device_info else '' }}</h1>

            {% if device_info and structured_data and 'miner_info' in structured_data %}
                <p>Всего IP: {{ structured_data['miner_info']['ip_count'] }}</p>
                {% if structured_data['miner_info']['ip_count'] > 0 %}
                    {% for ip, cmd_data in structured_data['miner_info']['ip_data'].items() %}
                        <h4>IP: {{ ip }}</h4>
                        <table class="table table-bordered">
                            <thead>
                                <tr>
                                    <th style="width: 150px;">Команда</th>
                                    <th>Ответ</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for cmd, response in cmd_data.items() %}
                                <tr>
                                    <td>{{ cmd }}</td>
                                    <td>
                                        <div class="code-block">{{ response }}</div>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    {% endfor %}
                {% else %}
                    <p>Майнеры не найдены.</p>
                {% endif %}
            {% else %}
                <p>Нет данных по диагностике.</p>
            {% endif %}

            <a href="{{ previous_url }}" class="btn btn-primary">Назад</a>
        </div>
    </body>
    </html>
    '''

    return render_template_string(template,
                                 device_info=device_info,
                                 structured_data=structured_data)




@app.route('/users')
@auth_required
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
                    <a href="{{ url_for('user_summary', user_id=user.id) }}">Профиль</a> - 
                    <a href="{{ url_for('delete_user', user_id=user.id) }}">Удалить</a> - 
                    <a href="{{ url_for('reset_password_admin', user_id=user.id) }}">Сбросить пароль</a></li>
                {% endfor %}
            </ul>
            <h1>Менеджеры</h1>
            <ul>
                {% for user in managers %}
                <li>{{ user.username }} ({{ user.tariff.name if user.tariff else 'Без тарифа' }}) - 
                    <a href="{{ url_for('user_summary', user_id=user.id) }}">Профиль</a> - 
                    <a href="{{ url_for('delete_user', user_id=user.id) }}">Удалить</a> - 
                    <a href="{{ url_for('reset_password_admin', user_id=user.id) }}">Сбросить пароль</a></li>
                {% endfor %}
            </ul>
            <h1>Партнеры</h1>
            <ul>
                {% for user in partners %}
                <li>{{ user.username }} ({{ user.tariff.name if user.tariff else 'Без тарифа' }}) - 
                    <a href="{{ url_for('user_summary', user_id=user.id) }}">Профиль</a> - 
                    <a href="{{ url_for('delete_user', user_id=user.id) }}">Удалить</a> - 
                    <a href="{{ url_for('reset_password_admin', user_id=user.id) }}">Сбросить пароль</a></li>
                {% endfor %}
            </ul>
            <a href="/admin" class="btn btn-secondary btn-back">Назад</a>
        </div>
    </body>
    </html>
    ''', partners=partners, managers=managers, supervisors=supervisors)

    


@app.route('/user_summary/<int:user_id>', methods=['GET'])
@auth_required
@role_required('admin', 'partner', 'manager', 'supervisor', 'user')
def user_summary(user_id):
    user = User.query.get_or_404(user_id)
    balance = user.balance  # Получаем баланс из модели пользователя

    # Получаем все ключи, связанные с пользователем
    user_keys = UserKey.query.filter_by(user_id=user_id).all()
    total_keys = len(user_keys)

    # Подсчитываем количество ключей по статусам
    status_counts = Counter(key.status for key in user_keys)

    # Количество ключей на реализации (операции типа 'consignment')
    consignment_keys_ids = [op.product_id for op in UserOperation.query.filter_by(
        user_id=user_id,
        operation_type='consignment'
    ).all()]
    consignment_keys_count = len(consignment_keys_ids)

    # Количество проданных ключей (операции типа 'sale' со статусом 'confirmed')
    sold_keys_ids = [op.product_id for op in UserOperation.query.filter_by(
        user_id=user_id,
        operation_type='sale',
        status='confirmed'
    ).all()]
    sold_keys_count = len(sold_keys_ids)

    # Количество активированных ключей (статус ключа 'activated')
    activated_keys_count = UserKey.query.filter_by(
        user_id=user_id,
        status='activated'
    ).count()

    # Количество непроданных ключей на реализации
    unsold_consignment_keys_count = consignment_keys_count - sold_keys_count

    # Подготовка данных операций для отображения
    operations_data = []
    user_operations = UserOperation.query.filter_by(user_id=user_id).all()
    for op in user_operations:
        # Получаем объект ключа на основе product_id
        key = UserKey.query.get(op.product_id)
        key_value = key.key if key else 'N/A'

        operations_data.append({
            'id': op.id,
            'operation_type': op.operation_type,
            'amount': op.amount,
            'status': op.status,
            'date': op.date.strftime('%Y-%m-%d %H:%M:%S'),
            'key_value': key_value  # Добавляем значение ключа
        })

    # Передача данных в шаблон
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Профиль пользователя</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .profile {
            max-width: 1200px;
            margin: 50px auto;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            background-color: #f9f9f9;
        }
        .profile h1 {
            text-align: center;
            margin-bottom: 20px;
        }
        .profile a {
            display: block;
            margin: 10px 0;
            padding: 10px;
            background-color: #007bff;
            color: white;
            text-align: center;
            border-radius: 4px;
            text-decoration: none;
        }
        .profile a:hover {
            background-color: #0056b3;
        }
        .balance {
            text-align: center;
            font-size: 1.2em;
            margin-top: 20px;
            margin-bottom: 20px;
        }
        .stats {
            margin-top: 20px;
        }
        .stats h3 {
            margin-bottom: 15px;
        }
        .table-container {
            margin-top: 30px;
        }
        table {
            width: 100%;
            margin-bottom: 20px;
            border-collapse: collapse;
        }
        th, td {
            padding: 8px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        .btn-back {
            margin-bottom: 20px;
        }
        .table tbody tr:nth-child(even) {
            background-color: #f9f9f9;
        }
    </style>
</head>
<body>
    <div class="profile">
        <!-- Кнопка "Назад к списку пользователей" перемещена в верх -->
        <h1>Профиль пользователя: {{ user.username }}</h1>
        <a href="{{ url_for('list_users') }}" class="btn btn-secondary btn-back">Назад к списку пользователей</a>
        <a href="{{ url_for('edit_user', user_id=user.id) }}">Редактировать профиль</a>
        <a href="{{ url_for('manage_keys', user_id=user.id) }}">Управление ключами</a>
        <div class="balance">
            <strong>Баланс: </strong>{{ balance }} ₽
        </div>

        <!-- Общие показатели -->
        <div class="stats">
            <h3>Общие показатели</h3>
            <table class="table">
                <tbody>
                    <tr>
                        <th>Общее количество ключей:</th>
                        <td>{{ total_keys }}</td>
                    </tr>
                    <tr>
                        <th>Ключей на реализации:</th>
                        <td>{{ consignment_keys_count }}</td>
                    </tr>
                    <tr>
                        <th>Проданных ключей:</th>
                        <td>{{ sold_keys_count }}</td>
                    </tr>
                    <tr>
                        <th>Активированных ключей:</th>
                        <td>{{ activated_keys_count }}</td>
                    </tr>
                    <tr>
                        <th>Непроданных ключей на реализации:</th>
                        <td>{{ unsold_consignment_keys_count }}</td>
                    </tr>
                    {% for status, count in status_counts.items() %}
                    <tr>
                        <th>Ключей со статусом "{{ status }}":</th>
                        <td>{{ count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Таблица операций -->
        <div class="table-container">
            <h2>Операции</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Тип операции</th>
                        <th>Сумма</th>
                        <th>Статус</th>
                        <th>Дата</th>
                        <th>Ключ</th>
                    </tr>
                </thead>
                <tbody>
                    {% for op in operations_data %}
                    <tr>
                        <td>{{ op.id }}</td>
                        <td>
                            {% if op.operation_type == 'sale' %}Продажа
                            {% elif op.operation_type == 'consignment' %}Реализация
                            {% elif op.operation_type == 'manual_add' %}Ручное добавление
                            {% elif op.operation_type == 'return' %}Возврат
                            {% else %}{{ op.operation_type }}{% endif %}
                        </td>
                        <td>{{ op.amount }}</td>
                        <td>
                            {% if op.status == 'pending' %}В ожидании
                            {% elif op.status == 'confirmed' %}Подтверждено
                            {% elif op.status == 'cancelled' %}Отменено
                            {% else %}{{ op.status }}{% endif %}
                        </td>
                        <td>{{ op.date }}</td>
                        <td>{{ op.key_value }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Таблица ключей на реализации -->
        <div class="table-container">
            <h2>Ключи на реализации</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Ключ</th>
                        <th>Статус</th>
                        <th>Дата начала</th>
                        <th>Дата окончания</th>
                    </tr>
                </thead>
                <tbody>
                    {% for key in user_keys %}
                    {% if key.id in consignment_keys_ids and key.id not in sold_keys_ids %}
                    <tr>
                        <td>{{ key.key }}</td>
                        <td>{{ key.status }}</td>
                        <td>{{ key.start_date }}</td>
                        <td>{{ key.end_date }}</td>
                    </tr>
                    {% endif %}
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
    ''', user=user, balance=balance, total_keys=total_keys,
       consignment_keys_count=consignment_keys_count,
       sold_keys_count=sold_keys_count,
       activated_keys_count=activated_keys_count,
       unsold_consignment_keys_count=unsold_consignment_keys_count,
       status_counts=status_counts,
       operations_data=operations_data,
       user_keys=user_keys,
       consignment_keys_ids=consignment_keys_ids,
       sold_keys_ids=sold_keys_ids)



@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Пользователь удален')
    return redirect(url_for('list_users'))

@app.route('/reset_password_admin/<int:user_id>', methods=['GET', 'POST'])
@auth_required
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
@auth_required
@role_required('supervisor')
def supervisor_dashboard():
    supervisor_id = g.user.id  # Используем ID текущего пользователя

    # Получение менеджеров, назначенных супервизору
    manager_associations = ManagerSupervisorAssociation.query.filter_by(supervisor_id=supervisor_id).all()
    managers = [User.query.filter_by(id=assoc.manager_id).first() for assoc in manager_associations if User.query.filter_by(id=assoc.manager_id).first()]

    # Получение партнёров, назначенных менеджерам
    partners = {}
    for manager in managers:
        partner_associations = PartnerManagerAssociation.query.filter_by(manager_id=manager.id).all()
        partner_list = [User.query.filter_by(id=assoc.partner_id).first() for assoc in partner_associations if User.query.filter_by(id=assoc.partner_id).first()]
        partners[manager.id] = partner_list

    # Получение ключей для супервизора, менеджеров и партнёров
    supervisor_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.id == supervisor_id).all()
    manager_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.id.in_([m.id for m in managers])).all()
    partner_ids = [p.id for sublist in partners.values() for p in sublist]
    partner_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.id.in_(partner_ids)).all()

    # Создание словаря для отображения ключей партнёров
    partner_keys_dict = {
        partner.id: db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(UserKey.user_id == partner.id).all()
        for partner in [p for sublist in partners.values() for p in sublist]
    }

    # Подсчет устройств по статусам
    total_new_devices = len([key for key, user in partner_keys if key.status == 'new'])
    total_active_devices = len([key for key, user in partner_keys if key.status == 'active'])

    # Подсчет заработанных средств
    supervisor_tariff = g.user.tariff
    earnings = 0
    if supervisor_tariff:
        initial_earnings = db.session.query(Earning).filter(
            Earning.user_id == supervisor_id,
            Earning.description.like('Первоначальный заработок супервизора%')
        ).all()
        earnings = sum(e.amount for e in initial_earnings)

    # Получение информации о начислениях
    earnings_data = db.session.query(Earning).filter(Earning.user_id == supervisor_id).all()
    earnings_summary = sum(e.amount for e in earnings_data)
    percentage_earnings = earnings_summary - earnings

    # Получение тарифов, назначенных пользователям
    assigned_tariff_ids = {user.tariff_id for user in managers + [g.user] if user.tariff_id is not None}
    assigned_tariffs = Tariff.query.filter(Tariff.id.in_(assigned_tariff_ids)).all()

    # Вычисление остатка дней
    def calculate_days_left(end_date):
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d %H:%M:%S')
                days_left = (end_date - datetime.now()).days
                return days_left if days_left > 0 else 0
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
                    start_date = datetime.strptime(key.start_date, '%Y-%m-%d %H:%M:%S')
                    end_date = datetime.strptime(key.end_date, '%Y-%m-%d %H:%M:%S')
                    duration_days = (end_date - start_date).days
                    new_description = f'{earning.description} за {duration_days} дней, с {start_date.strftime("%Y-%m-%d")} по {end_date.strftime("%Y-%m-%d")}, по тарифу {tariff.name}'
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

                var buttons = document.querySelectorAll('.btn-status[data-partner="' + partnerId + '"]');
                buttons.forEach(function(btn) {
                    btn.classList.remove('active');
                });
                document.querySelector('.btn-status[data-partner="' + partnerId + '"][data-status="' + status + '"]').classList.add('active');
            }

            document.addEventListener('DOMContentLoaded', function() {
                var statusButtons = document.querySelectorAll('.btn-status');
                statusButtons.forEach(function(button) {
                    button.addEventListener('click', function() {
                        var partnerId = button.dataset.partner;
                        var status = button.dataset.status;
                        togglePartnerKeys(partnerId, status);
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
                <!-- Таб Менеджеры -->
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
                                        <button type="button" class="btn-status" data-partner="{{ partner.id }}" data-status="new">New</button>
                                        <button type="button" class="btn-status active" data-partner="{{ partner.id }}" data-status="active">Active</button>
                                        <button type="button" class="btn-status" data-partner="{{ partner.id }}" data-status="all">All</button>
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
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% endfor %}
                </div>
                <!-- Таб Ключи -->
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
                                    <th>Пользователь</th>
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
                                    <th>Пользователь</th>
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
                                    <th>Пользователь</th>
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
                <!-- Таб Тарифы -->
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
                                <td>{{ g.user.username }}</td>
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
@auth_required
@role_required('partner')
def partner_dashboard():
    partner_id = g.user.id  # Используем идентификатор партнёра из g.user.id

    # Получение менеджера, назначенного партнёру
    manager_association = PartnerManagerAssociation.query.filter_by(partner_id=partner_id).first()
    manager = User.query.filter_by(id=manager_association.manager_id).first() if manager_association else None

    # Получение супервизора, назначенного менеджеру
    supervisor = None
    if manager:
        supervisor_association = ManagerSupervisorAssociation.query.filter_by(manager_id=manager.id).first()
        supervisor = User.query.filter_by(id=supervisor_association.supervisor_id).first() if supervisor_association else None

    # Получение ключей для партнёра
    partner_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.role == 'partner', User.id == g.user.id).all()

    # Подсчет устройств по статусам
    total_new_devices = len([key for key, user in partner_keys if key.status == 'new'])
    total_active_devices = len([key for key, user in partner_keys if key.status == 'active'])
    
    # Подсчет заработанных средств
    partner_tariff = g.user.tariff
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

            document.addEventListener('DOMContentLoaded', function() {
                var links = document.querySelectorAll('.nav-link');
                links.forEach(function(link) {
                    link.addEventListener('click', function(event) {
                        event.preventDefault();
                    });
                });

                var statusButtons = document.querySelectorAll('.btn-status');
                statusButtons.forEach(function(button) {
                    button.addEventListener('click', function() {
                        var status = button.dataset.status;
                        togglePartnerKeys(status);
                        
                        var buttons = document.querySelectorAll('.btn-status');
                        buttons.forEach(function(btn) {
                            btn.classList.remove('active');
                        });

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
@auth_required
@role_required('manager')
def manager_dashboard():
    manager_id = g.user.id  # Используем ID текущего пользователя

    # Получение супервизора, назначенного менеджеру
    supervisor_association = ManagerSupervisorAssociation.query.filter_by(manager_id=manager_id).first()
    supervisor = User.query.filter_by(id=supervisor_association.supervisor_id).first() if supervisor_association else None

    # Получение партнёров, назначенных менеджеру
    partner_associations = PartnerManagerAssociation.query.filter_by(manager_id=manager_id).all()
    partners = [User.query.filter_by(id=association.partner_id).first() for association in partner_associations]

    # Получение ключей для менеджера и его партнёров
    manager_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.id == manager_id).all()
    partner_keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(User.id.in_([p.id for p in partners])).all()

    # Создание словаря для отображения ключей партнёров
    partner_keys_dict = {}
    for partner in partners:
        keys = db.session.query(UserKey, User).join(User, UserKey.user_id == User.id).filter(UserKey.user_id == partner.id).all()
        partner_keys_dict[partner.id] = keys

    # Подсчет устройств по статусам
    total_new_devices = len([key for key, user in partner_keys if key.status == 'new'])
    total_active_devices = len([key for key, user in partner_keys if key.status == 'active'])
    
    # Подсчет заработанных средств
    manager_tariff = g.user.tariff  # Используем g.user вместо current_user
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
            return max(0, (end_date - datetime.now()).days)
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

                var buttons = document.querySelectorAll('.btn-status[data-partner="' + partnerId + '"]');
                buttons.forEach(function(btn) {
                    btn.classList.remove('active');
                });
                document.querySelector('.btn-status[data-partner="' + partnerId + '"][data-status="' + status + '"]').classList.add('active');
            }

            document.addEventListener('DOMContentLoaded', function() {
                var statusButtons = document.querySelectorAll('.btn-status');
                statusButtons.forEach(function(button) {
                    button.addEventListener('click', function() {
                        var partnerId = button.dataset.partner;
                        var status = button.dataset.status;
                        togglePartnerKeys(partnerId, status);
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
                <!-- Супервизор -->
                <div class="tab-pane fade show active" id="supervisor" role="tabpanel" aria-labelledby="supervisor-tab">
                    <h2>Супервизор</h2>
                    {% if supervisor %}
                    <p>Супервизор: {{ supervisor.username }}</p>
                    <p>Email: {{ supervisor.email }}</p>
                    {% else %}
                    <p>Супервизор не назначен.</p>
                    {% endif %}
                </div>
                <!-- Партнёры -->
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
                            <button type="button" class="btn-status" data-partner="{{ partner.id }}" data-status="new">New</button>
                            <button type="button" class="btn-status active" data-partner="{{ partner.id }}" data-status="active">Active</button>
                            <button type="button" class="btn-status" data-partner="{{ partner.id }}" data-status="all">All</button>
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
                <!-- Тарифы -->
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
                                <td>{{ g.user.username }}</td>
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
        users = pd.read_sql_query("SELECT id, email, phone_number, password FROM users", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data", conn)
    elif role == 'partner':
        users = pd.read_sql_query("SELECT id, email, phone_number, password FROM users WHERE role = 'partner'", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs WHERE user_id IN (SELECT id FROM users WHERE role = 'partner')", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys WHERE user_id IN (SELECT id FROM users WHERE role = 'partner')", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data WHERE user_id IN (SELECT id FROM users WHERE role = 'partner')", conn)
    elif role == 'manager':
        users = pd.read_sql_query("SELECT id, email, phone_number, password FROM users WHERE role = 'manager'", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs WHERE user_id IN (SELECT id FROM users WHERE role = 'manager')", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys WHERE user_id IN (SELECT id FROM users WHERE role = 'manager')", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data WHERE user_id IN (SELECT id FROM users WHERE role = 'manager')", conn)
    else:
        users = pd.read_sql_query("SELECT id, email, phone_number, password FROM users", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data", conn)

    conn.close()
    return users, user_tariffs, tariffs, user_keys, miner_data







@app.route('/keys_management', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def keys_management_view():
    page = request.args.get('page', 1, type=int)
    per_page = 500  # Установлено отображение 500 записей на странице
    start_date = request.args.get('start_date') if request.method == 'GET' else request.form.get('start_date')

    role = g.user.role
    users, user_tariffs, tariffs, user_keys, miner_data = get_data_for_user(role)

    # Объединение данных ключей с тарифами
    user_keys_with_tariffs = user_keys.merge(
        tariffs,
        left_on='tariff_id',
        right_on='tariff_id',
        how='left',
        suffixes=('', '_tariffs')
    )

    # Объединение данных пользователей с ключами
    merged_data = users.merge(
        user_keys_with_tariffs,
        left_on='id',
        right_on='user_id',
        how='left',
        suffixes=('', '_user_keys')
    )

    # Заполнение пропущенных значений
    merged_data['email'].fillna('', inplace=True)
    merged_data['phone_number'].fillna('', inplace=True)
    if 'key_name' in merged_data.columns:
        merged_data['key_name'].fillna('Без названия', inplace=True)
    else:
        merged_data['key_name'] = 'Без названия'

    merged_data['start_date'].fillna('N/A', inplace=True)
    merged_data['end_date'].fillna('N/A', inplace=True)
    merged_data['status'].fillna('N/A', inplace=True)
    merged_data['name'].fillna('Без тарифа', inplace=True)

    # Форматирование данных для отображения
    def format_date(x):
        if x != 'N/A':
            try:
                return pd.to_datetime(x).strftime('%Y-%m-%d %H:%M:%S')
            except:
                return x
        else:
            return x

    merged_data['start_date'] = merged_data['start_date'].apply(format_date)
    merged_data['end_date'] = merged_data['end_date'].apply(format_date)

    # Создание идентификатора пользователя для входа
    def get_identifier(row):
        if row['email']:
            return row['email']
        elif row['phone_number']:
            return row['phone_number']
        else:
            return 'user_{}'.format(row['id'])

    merged_data['identifier'] = merged_data.apply(get_identifier, axis=1)

    # Преобразование данных в словарь
    user_keys_dict = {}
    for identifier, group in merged_data.groupby('identifier'):
        user_info = group.iloc[0]
        user_keys_dict[identifier] = {
            'email': user_info['email'] if user_info['email'] else 'Нет почты',
            'phone_number': user_info['phone_number'] if user_info['phone_number'] else 'Нет телефона',
            'keys': group[['key', 'key_name', 'start_date', 'end_date', 'status', 'name']].to_dict(orient='records')
        }

    # Пагинация
    total = len(user_keys_dict)
    start = (page - 1) * per_page
    end = start + per_page if per_page != -1 else total
    items = list(user_keys_dict.items())
    paginated_user_keys_dict = dict(items[start:end])

    # Шаблон для отображения таблицы
    template = '''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
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
                width: 200px;
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
                padding: 6px;
                text-align: left;
                vertical-align: top;
                white-space: nowrap;
            }
            th {
                background-color: #f2f2f2;
                cursor: pointer;
                position: relative;
            }
            tr:hover {
                background-color: #f5f5f5;
            }
            .key-entry {
                margin-bottom: 10px;
                padding: 8px;
                border-bottom: 1px solid #ddd;
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
            .email-column, .phone-column, .status-column, .tariff-column, .login-column {
                width: 120px;
            }
            .key-name-column, .date-column {
                width: 220px;
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

            function filterTable() {
                const filterInputs = document.querySelectorAll('.filter-container input');
                const table = document.getElementById("summaryTable");
                const rows = Array.from(table.querySelectorAll("tbody tr"));

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
            }
        </script>
    </head>
    <body>
        <h1>Управление ключами</h1>
        <div class="filter-container">
            <input type="text" placeholder="Фильтр по Email">
            <input type="text" placeholder="Фильтр по Телефону">
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
                        <th>#</th>
                        <th>Email</th>
                        <th>Телефон</th>
                        <th>Ключи</th>
                        <th>Названия ключей</th>
                        <th>Даты начала</th>
                        <th>Даты окончания</th>
                        <th>Статусы</th>
                        <th>Тарифы</th>
                        <th>Вход</th>
                    </tr>
                </thead>
                <tbody>
                    {% set i = 1 %}
                    {% for identifier, data in paginated_user_keys_dict.items() %}
                    <tr>
                        <td>{{ i }}</td>
                        <td class="email-column">{{ data['email'] }}</td>
                        <td class="phone-column">{{ data['phone_number'] }}</td>
                        <td>
                            {% for key in data['keys'] %}
                                <div class="key-entry">{{ key['key'] }}</div>
                            {% endfor %}
                        </td>
                        <td class="key-name-column">
                            {% for key in data['keys'] %}
                                <div class="key-entry">{{ key['key_name'] }}</div>
                            {% endfor %}
                        </td>
                        <td class="date-column">
                            {% for key in data['keys'] %}
                                <div class="key-entry">{{ key['start_date'] }}</div>
                            {% endfor %}
                        </td>
                        <td class="date-column">
                            {% for key in data['keys'] %}
                                <div class="key-entry">{{ key['end_date'] }}</div>
                            {% endfor %}
                        </td>
                        <td class="status-column">
                            {% for key in data['keys'] %}
                                <div class="key-entry">{{ key['status'] }}</div>
                            {% endfor %}
                        </td>
                        <td class="tariff-column">
                            {% for key in data['keys'] %}
                                <div class="key-entry">{{ key['name'] }}</div>
                            {% endfor %}
                        </td>
                        <td class="login-column">
                            <form action="{{ url_for('client_details', identifier=identifier) }}" method="get">
                                <button type="submit" class="login-btn">Вход</button>
                            </form>
                        </td>
                    </tr>
                    {% set i = i + 1 %}
                    {% endfor %}
                </tbody>
            </table>
            <!-- Пагинация -->
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

    return render_template_string(
        template,
        paginated_user_keys_dict=paginated_user_keys_dict,
        start_date=start_date,
        page=page,
        per_page=per_page,
        total=total
    )

    
@app.route('/client/<identifier>', methods=['GET'])
@auth_required
@role_required('admin')
def client_details(identifier):
    role = g.user.role
    users, user_tariffs, tariffs, user_keys, miner_data = get_data_for_user(role)

    # Объединение данных ключей с тарифами
    user_keys_with_tariffs = user_keys.merge(
        tariffs, left_on='tariff_id', right_on='tariff_id',
        how='left', suffixes=('', '_tariffs')
    )

    # Объединение данных пользователей с ключами
    merged_data = users.merge(
        user_keys_with_tariffs, left_on='id', right_on='user_id',
        how='left', suffixes=('', '_user_keys')
    )

    # Поиск по email или телефону
    if '@' in identifier:
        client_data = merged_data[merged_data['email'] == identifier]
        if client_data.empty:
            return "User not found", 404
        user_info = users[users['email'] == identifier].iloc[0]
    else:
        # Проверяем, есть ли столбец 'phone_number' в DataFrame users
        if 'phone_number' in users.columns:
            client_data = merged_data[merged_data['phone_number'] == identifier]
            if client_data.empty:
                return "User not found", 404
            user_info = users[users['phone_number'] == identifier].iloc[0]
        else:
            return "Phone number column not found", 400

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

    # Подключение к базе данных для проверки статуса ключа
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

    # Выбор данных конкретного пользователя
    client_data = merged_data[merged_data['user_id'] == user_info['id']]

    # Данные по платежам конкретного пользователя
    client_payments = payments_df[payments_df['user_id'] == user_info['id']]

    # Подключение к базе данных instance/users.db для извлечения данных о партнёрах и ключах
    partner_db_engine = create_engine('sqlite:///' + os.path.join(BASE_DIR, 'instance/users.db'))
    partner_connection = partner_db_engine.connect()

    # Извлечение данных о ключах и партнёрах
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
        <h2>{{ user_info['email'] if 'email' in user_info else user_info['phone_number'] }}</h2>
        <table class="client-info table table-bordered">
            {% if 'phone_number' in user_info %}
            <tr>
                <th>Телефон</th>
                <td>{{ user_info['phone_number'] }}</td>
            </tr>
            {% endif %}
            {% if 'email' in user_info %}
            <tr>
                <th>Почта</th>
                <td>{{ user_info['email'] }}</td>
            </tr>
            {% endif %}
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

    return render_template_string(template, client_data=client_data, user_info=user_info, client_payments=client_payments, partner_keys_df=partner_keys_df)





# Обработка данных и отображение сводной таблицы
@app.route('/data')
@auth_required
@role_required('admin')
def data_view():
    role = g.user.role
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
    summary_table = merged_data[['id', 'email','phone_number', 'name', 'start_date', 'end_date', 'devices_count', 'ltc_hashrate', 'btc_hashrate', 'key_count', 'keys']]
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

                # Расчет хэшрейтов и количества устройств для LTC
                miner_hashrate_ltc = round(miner_data[miner_data['device_model'].str.contains('Antminer L3+|Antminer L7|Antminer L9|DG1\+', na=False)]['mhs_av'].sum(), 2)
                miner_devices_ltc = miner_data[miner_data['device_model'].str.contains('Antminer L3+|Antminer L7|Antminer L9|DG1\+', na=False)].shape[0]

                # Расчет хэшрейтов и количества устройств для BTC
                miner_hashrate_btc = round(miner_data[~miner_data['device_model'].str.contains('Antminer L3+|Antminer L7|Antminer L9|DG1\+', na=False)]['mhs_av'].sum(), 2)
                miner_devices_btc = miner_data[~miner_data['device_model'].str.contains('Antminer L3+|Antminer L7|Antminer L9|DG1\+', na=False)].shape[0]

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
@auth_required
@role_required('admin')
def daily_metrics():
    conn_main = get_db_connection()  # Подключение к основной базе
    conn_secondary = sqlite3.connect(SECONDARY_DATABASE_PATH)  # Подключение к базе с user_keys

    try:
        today = datetime.now().date()
        yesterday = today - timedelta(days=1)

        # Получение данных из daily_metrics
        query = '''
        SELECT date, total_ltc_hashrate, total_btc_hashrate, total_ltc_devices, total_btc_devices, total_keys
        FROM daily_metrics
        WHERE date IN (?, ?)
        '''
        df = pd.read_sql_query(query, conn_main, params=[str(yesterday), str(today)])
        df['date'] = pd.to_datetime(df['date']).dt.date

        # Подсчёт активаций на основе start_date в user_keys
        activations_today = conn_secondary.execute(
            "SELECT COUNT(*) FROM user_keys WHERE DATE(start_date) = ?", (today,)
        ).fetchone()[0]

        activations_yesterday = conn_secondary.execute(
            "SELECT COUNT(*) FROM user_keys WHERE DATE(start_date) = ?", (yesterday,)
        ).fetchone()[0]

        # Формируем метрики
        metrics = {
            'labels': ['Хэшрейт LTC', 'Хэшрейт BTC', 'Асики LTC', 'Асики BTC', 'Всего устройств', 'Активации'],
            'today': df[df['date'] == today].sum(numeric_only=True).fillna(0).tolist() + [activations_today],
            'yesterday': df[df['date'] == yesterday].sum(numeric_only=True).fillna(0).tolist() + [activations_yesterday],
            'growth': []
        }

        for today_val, yesterday_val in zip(metrics['today'], metrics['yesterday']):
            if yesterday_val > 0:
                metrics['growth'].append(round(((today_val - yesterday_val) / yesterday_val) * 100, 2))
            else:
                metrics['growth'].append(0)
    finally:
        conn_main.close()
        conn_secondary.close()

    # Формирование HTML для отображения данных
    html = """<!DOCTYPE html>
<html lang=\"ru\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Ежедневные метрики</title>
    <meta http-equiv=\"refresh\" content=\"5\">
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            background-color: #f2f2f2;
            color: #333;
        }
        .container {
            margin: 20px;
        }
        table {
            margin: 20px auto;
            border-collapse: collapse;
            width: 80%;
        }
        th, td {
            border: 1px solid #ccc;
            padding: 10px;
            text-align: center;
        }
        th {
            background-color: #f4f4f4;
        }
        .highlight {
            font-weight: bold;
            color: green;
        }
        .negative {
            color: red;
        }
    </style>
</head>
<body>
    <div class=\"container\">
        <h1>Ежедневные метрики</h1>
        <p>Обновление данных каждые 5 секунд</p>
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
    """

    for label, today, yesterday, growth in zip(metrics['labels'], metrics['today'], metrics['yesterday'], metrics['growth']):
        growth_class = "highlight" if growth > 0 else "negative"
        html += f"""
            <tr>
                <td>{label}</td>
                <td>{today}</td>
                <td>{yesterday}</td>
                <td class=\"{growth_class}\">{growth}%</td>
            </tr>
        """

    html += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""

    return html


@app.route('/partner_statistics', methods=['GET'])
@auth_required
#@role_required('admin', 'partner', 'manager', 'supervisor', 'user')
def partner_statistics():
    conn = sqlite3.connect(DATABASE_PATH)

    # Получение параметров запроса
    start_date = request.args.get('start_date', None)
    end_date = request.args.get('end_date', None)
    selected_partner = request.args.get('partner', None)

    # Если даты не указаны, выбираем последние 7 дней
    if not start_date or not end_date:
        today_date = datetime.now().date()
        end_date = today_date.isoformat()
        start_date = (today_date - timedelta(days=6)).isoformat()

    # Если параметр партнёра пришёл в виде списка – берём первый элемент
    if isinstance(selected_partner, list):
        selected_partner = selected_partner[0]

    try:
        # Запрос для статистики за выбранный период
        query_period = '''
        SELECT u.username AS partner_name,
               DATE(k.start_date) AS activation_date,
               COUNT(k.id) AS activated_devices
        FROM user_key k
        LEFT JOIN user u ON k.user_id = u.id
        WHERE k.status IN ('active', 'inactive')
          AND DATE(k.start_date) BETWEEN ? AND ?
        GROUP BY u.username, DATE(k.start_date)
        ORDER BY u.username, DATE(k.start_date)
        '''
        params = [start_date, end_date]
        stats_period = pd.read_sql_query(query_period, conn, params=params)
        stats_period['activation_date'] = pd.to_datetime(stats_period['activation_date']).dt.strftime('%d.%m.%y')

        # Фильтрация по партнёру, если выбран конкретный
        if selected_partner and selected_partner != "all":
            stats_period = stats_period[stats_period['partner_name'] == selected_partner]

        # Формирование списка партнёров (только тех, у кого есть активации за период)
        partners = stats_period['partner_name'].unique().tolist()

        # Подсчёт статистики за выбранный период и за сегодня
        today_str = datetime.now().strftime('%d.%m.%y')
        period_stats = {}
        today_stats = {}
        partner_details = {}
        for partner in partners:
            df_partner = stats_period[stats_period['partner_name'] == partner]
            period_total = df_partner['activated_devices'].sum() if not df_partner.empty else 0
            period_stats[partner] = period_total

            df_today = df_partner[df_partner['activation_date'] == today_str]
            today_count = df_today['activated_devices'].sum() if not df_today.empty else 0
            today_stats[partner] = today_count

            details = (df_partner[['activation_date', 'activated_devices']]
                       .drop_duplicates().to_dict('records')
                       if not df_partner.empty else [])
            partner_details[partner] = details

        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Статистика за период</title>
  <style>
      body {{
          font-family: Arial, sans-serif;
          text-align: center;
          background-color: #f2f2f2;
          color: #333;
      }}
      .container {{
          width: 90%;
          margin: 0 auto;
      }}
      table {{
          margin: 20px auto;
          border-collapse: collapse;
          width: 100%;
      }}
      th, td {{
          border: 1px solid #ccc;
          padding: 10px;
          text-align: center;
      }}
      th {{
          background-color: #f4f4f4;
      }}
      form {{
          margin-bottom: 20px;
      }}
      form label {{
          margin: 0 10px;
      }}
      .details {{
          display: none;
      }}
      .toggle-btn {{
          cursor: pointer;
          color: blue;
          text-decoration: underline;
          font-size: 0.9em;
          margin-left: 10px;
      }}
      .back-btn {{
          margin-top: 20px;
          display: inline-block;
          padding: 10px 20px;
          background-color: #6c757d;
          color: #fff;
          text-decoration: none;
          border-radius: 4px;
      }}
      .back-btn:hover {{
          background-color: #5a6268;
      }}
  </style>
  <script>
      function toggleDetails(id) {{
          var detailsRow = document.getElementById(id);
          if(detailsRow.style.display === 'none' || detailsRow.style.display === '') {{
              detailsRow.style.display = 'table-row';
          }} else {{
              detailsRow.style.display = 'none';
          }}
      }}
      
      function resetDates() {{
          var today = new Date().toISOString().split('T')[0];
          document.getElementById('startDate').value = today;
          document.getElementById('endDate').value = today;
      }}
  </script>
</head>
<body>
  <div class="container">
      <h1>Статистика за период</h1>
      <form id="filterForm">
          <label for="startDate">Начальная дата:</label>
          <input type="date" id="startDate" name="start_date" value="{start_date}">
          <label for="endDate">Конечная дата:</label>
          <input type="date" id="endDate" name="end_date" value="{end_date}">
          <button type="button" onclick="resetDates()">Сбросить дату</button>
          <label for="partner">Партнёр:</label>
          <select id="partner" name="partner">
              <option value="all">Все</option>
"""
        # Опции для выбора партнёров (из выборки за период)
        all_partners = stats_period['partner_name'].unique().tolist()
        for partner in all_partners:
            selected_attr = 'selected' if selected_partner == partner else ''
            html += f'              <option value="{partner}" {selected_attr}>{partner}</option>\n'
        html += """          </select>
          <button type="submit">Применить</button>
      </form>
      
      <!-- Таблица со статистикой за выбранный период -->
      <table>
          <thead>
              <tr>
                  <th>Партнёр</th>
                  <th>За период</th>
                  <th>За сегодня</th>
              </tr>
          </thead>
          <tbody>
"""
        for partner in partners:
            period_total = period_stats.get(partner, 0)
            today_count = today_stats.get(partner, 0)
            row_id = f"details_{partner.replace(' ', '_')}"
            html += f"""              <tr>
                  <td>{partner} <span class="toggle-btn" onclick="toggleDetails('{row_id}')">Показать детали</span></td>
                  <td>{period_total}</td>
                  <td>{today_count}</td>
              </tr>
              <tr id="{row_id}" class="details">
                  <td colspan="3">
                      <table style="width: 100%; border: none;">
                          <thead>
                              <tr>
                                  <th>Дата</th>
                                  <th>Активации</th>
                              </tr>
                          </thead>
                          <tbody>
"""
            details = partner_details.get(partner, [])
            for detail in details:
                d = detail.get('activation_date', '')
                count = detail.get('activated_devices', 0)
                html += f"""                              <tr>
                                  <td>{d}</td>
                                  <td>{count}</td>
                              </tr>
"""
            html += """                          </tbody>
                      </table>
                  </td>
              </tr>
"""
        html += f"""          </tbody>
      </table>
      
      <p><a href="/partner_statistics/all_time">Посмотреть статистику за всё время</a></p>
      <p><a href="/dashboard" class="back-btn">Назад на панель управления</a></p>
  </div>
</body>
</html>
"""
        return html
    except Exception as e:
        print(f"Error: {e}")
        return "Ошибка при получении данных", 500
    finally:
        conn.close()


@app.route('/partner_statistics/all_time', methods=['GET'])
@auth_required
#@role_required('admin', 'partner', 'manager', 'supervisor', 'user')
def partner_statistics_all_time():
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        # Запрос для получения общей статистики "за всё время" (только партнеры с активациями)
        query_all = '''
        SELECT u.username AS partner_name,
               COUNT(k.id) AS activated_devices_all_time
        FROM user_key k
        LEFT JOIN user u ON k.user_id = u.id
        WHERE k.status IN ('active', 'inactive')
        GROUP BY u.username
        HAVING COUNT(k.id) > 0
        ORDER BY u.username
        '''
        stats_all = pd.read_sql_query(query_all, conn)
        total_all_time = stats_all.set_index('partner_name')['activated_devices_all_time'].to_dict()

        # Формирование списка партнеров для отображения
        partners = list(total_all_time.keys())
        overall_total_footer = sum(total_all_time.values())

        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Статистика за всё время</title>
  <style>
      body {{
          font-family: Arial, sans-serif;
          text-align: center;
          background-color: #f2f2f2;
          color: #333;
      }}
      .container {{
          width: 90%;
          margin: 0 auto;
      }}
      table {{
          margin: 20px auto;
          border-collapse: collapse;
          width: 100%;
      }}
      th, td {{
          border: 1px solid #ccc;
          padding: 10px;
          text-align: center;
      }}
      th {{
          background-color: #f4f4f4;
      }}
      .back-btn {{
          margin-top: 20px;
          display: inline-block;
          padding: 10px 20px;
          background-color: #6c757d;
          color: #fff;
          text-decoration: none;
          border-radius: 4px;
      }}
      .back-btn:hover {{
          background-color: #5a6268;
      }}
  </style>
</head>
<body>
  <div class="container">
      <h1>Статистика за всё время</h1>
      <table>
          <thead>
              <tr>
                  <th>Партнёр</th>
                  <th>Итого за всё время</th>
              </tr>
          </thead>
          <tbody>
"""
        for partner in partners:
            overall = total_all_time.get(partner, 0)
            html += f"""              <tr>
                  <td>{partner}</td>
                  <td>{overall}</td>
              </tr>
"""
        html += f"""          </tbody>
          <tfoot>
              <tr>
                  <td>Общий итог</td>
                  <td>{overall_total_footer}</td>
              </tr>
          </tfoot>
      </table>
      <p><a href="/dashboard" class="back-btn">Назад на панель управления</a></p>
      <p><a href="/partner_statistics">Назад к статистике за период</a></p>
  </div>
</body>
</html>
"""
        return html
    except Exception as e:
        print(f"Error: {e}")
        return "Ошибка при получении данных", 500
    finally:
        conn.close()




# Определение пути к файлу базы данных
db_path = "/root/cabinet/instance/metrics.db"

# Запуск функции periodic_save в отдельном потоке
thread = threading.Thread(target=periodic_save, args=(SECONDARY_DATABASE_PATH, db_path, 86400))  # Сохранение раз в сутки (86400 секунд)
thread.daemon = True
thread.start()

# Маршруты для управления тарифами
@app.route('/create_tariff', methods=['GET', 'POST'])
@auth_required
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
@auth_required
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
@auth_required
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
@auth_required
@role_required('admin')
def delete_tariff(tariff_id):
    tariff = Tariff.query.get_or_404(tariff_id)
    db.session.delete(tariff)
    db.session.commit()
    flash('Тариф удален')
    return redirect(url_for('list_tariffs'))

@app.route('/assign_partner_manager', methods=['GET', 'POST'])
@auth_required
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


@app.route('/money')
@auth_required  # Предполагается, что auth_required и role_required уже определены
@role_required('admin')
def money_table():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        # Параметры запроса для сортировки, фильтрации по статусу обработки и по дате
        sort_by = request.args.get('sort_by', 'payment_date')
        order = request.args.get('order', 'desc')
        processed_filter = request.args.get('processed')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        # Условия для сортировки, фильтрации по статусу и по дате
        sort_order = 'ASC' if order == 'asc' else 'DESC'
        where_clauses = []
        params = []

        # Фильтр по статусу обработки
        if processed_filter in ['Да', 'Нет']:
            where_clauses.append("processed = ?")
            params.append(1 if processed_filter == 'Да' else 0)

        # Фильтр по дате платежа
        if start_date:
            where_clauses.append("payment_date >= ?")
            params.append(start_date)
        if end_date:
            where_clauses.append("payment_date <= ?")
            params.append(end_date)

        # Построение условия WHERE для SQL-запроса
        where_clause = 'WHERE ' + ' AND '.join(where_clauses) if where_clauses else ''

        # Запрос с сортировкой, фильтрацией, лимитом и смещением для пагинации
        query = f'''
        SELECT user_id, tariff_id, amount, extension_days, payment_date, key, payment_id, processed
        FROM payment
        {where_clause}
        ORDER BY {sort_by} {sort_order}
        LIMIT ? OFFSET ?
        '''
        page = request.args.get('page', 1, type=int)
        per_page = 20
        offset = (page - 1) * per_page
        params.extend([per_page, offset])

        # Выполнение запроса и создание DataFrame
        df = pd.read_sql_query(query, conn, params=params)
        df['payment_date'] = pd.to_datetime(df['payment_date']).dt.date
        data = df.to_dict(orient='records')

        # Общее количество записей для пагинации
        total_records_query = f'SELECT COUNT(*) FROM payment {where_clause}'
        total_records = conn.execute(total_records_query, params[:len(where_clauses)]).fetchone()[0]
        total_pages = math.ceil(total_records / per_page)
    finally:
        conn.close()

    return render_template_string(template, data=data, page=page, total_pages=total_pages, sort_by=sort_by, order=order, processed_filter=processed_filter, start_date=start_date, end_date=end_date)

template = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Таблица Платежей</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f2f9ff;
            color: #03396c;
            text-align: center;
            padding: 20px;
        }
        table {
            width: 80%;
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
        .pagination {
            display: flex;
            justify-content: center;
            margin-top: 20px;
        }
        .pagination a {
            margin: 0 5px;
            padding: 8px 16px;
            text-decoration: none;
            color: #03396c;
            border: 1px solid #03396c;
            border-radius: 5px;
            background-color: #b3d4fc;
        }
        .pagination a.active {
            font-weight: bold;
            background-color: #03396c;
            color: #ffffff;
        }
        .filter-form, .sort-links {
            margin: 10px;
        }
        .back-button {
            margin: 20px;
            padding: 10px 20px;
            color: #fff;
            background-color: #004d99;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
        }
        .back-button:hover {
            background-color: #003366;
        }
        @media (max-width: 576px) {
            body {
                padding: 10px;
            }
            table {
                width: 100%;
            }
            th, td {
                padding: 6px;
                font-size: 0.9rem;
            }
            .pagination a {
                padding: 6px 10px;
                font-size: 0.8rem;
            }
            .filter-form label, .filter-form input, .filter-form select {
                font-size: 0.9rem;
            }
            .back-button {
                padding: 8px 16px;
                font-size: 0.9rem;
            }
        }
    </style>
    <script>
        function closeDatepicker(element) {
            setTimeout(function() {
                element.blur();
            }, 0);
        }
    </script>
</head>
<body>
    <h1>Таблица Платежей</h1>

    <a href="https://cabinet.sovamonitoring.com/dashboard" class="back-button">Назад</a>

    <div class="filter-form">
        <form method="get" action="{{ url_for('money_table') }}">
            <label for="processed">Фильтр по статусу обработки:</label>
            <select name="processed" id="processed" onchange="this.form.submit()">
                <option value="">Все</option>
                <option value="Да" {% if processed_filter == 'Да' %}selected{% endif %}>Да</option>
                <option value="Нет" {% if processed_filter == 'Нет' %}selected{% endif %}>Нет</option>
            </select>
            <br>
            <label for="start_date">Дата с:</label>
            <input type="date" name="start_date" id="start_date" value="{{ start_date }}" onchange="closeDatepicker(this)">
            <label for="end_date">по:</label>
            <input type="date" name="end_date" id="end_date" value="{{ end_date }}" onchange="closeDatepicker(this)">
            <button type="submit">Применить</button>
            <input type="hidden" name="sort_by" value="{{ sort_by }}">
            <input type="hidden" name="order" value="{{ order }}">
        </form>
    </div>

    <div class="sort-links">
        {% for column, label in [('user_id', 'User ID'), ('tariff_id', 'Тариф'), ('amount', 'Сумма'), ('extension_days', 'Продления (дни)'), ('payment_date', 'Дата платежа'), ('key', 'Ключ'), ('payment_id', 'ID платежа'), ('processed', 'Обработан')] %}
            <a href="{{ url_for('money_table', sort_by=column, order='asc' if order == 'desc' or sort_by != column else 'desc', processed=processed_filter, start_date=start_date, end_date=end_date) }}">
                {{ label }} {% if sort_by == column %}{{ '▲' if order == 'asc' else '▼' }}{% endif %}
            </a> |
        {% endfor %}
    </div>

    <table>
        <thead>
            <tr>
                <th>User ID</th>
                <th>Тариф</th>
                <th>Сумма</th>
                <th>Продления (дни)</th>
                <th>Дата платежа</th>
                <th>Ключ</th>
                <th>ID платежа</th>
                <th>Обработан</th>
            </tr>
        </thead>
        <tbody>
            {% for row in data %}
            <tr>
                <td>{{ row['user_id'] }}</td>
                <td>{{ row['tariff_id'] }}</td>
                <td>{{ row['amount'] }}</td>
                <td>{{ row['extension_days'] }}</td>
                <td>{{ row['payment_date'] }}</td>
                <td>{{ row['key'] }}</td>
                <td>{{ row['payment_id'] }}</td>
                <td>{{ 'Да' if row['processed'] else 'Нет' }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    
    <div class="pagination">
        {% if page > 1 %}
            <a href="{{ url_for('money_table', page=page-1, sort_by=sort_by, order=order, processed=processed_filter, start_date=start_date, end_date=end_date) }}">Назад</a>
        {% endif %}
        {% for p in range(1, total_pages + 1) %}
            <a href="{{ url_for('money_table', page=p, sort_by=sort_by, order=order, processed=processed_filter, start_date=start_date, end_date=end_date) }}" class="{{ 'active' if p == page else '' }}">{{ p }}</a>
        {% endfor %}
        {% if page < total_pages %}
            <a href="{{ url_for('money_table', page=page+1, sort_by=sort_by, order=order, processed=processed_filter, start_date=start_date, end_date=end_date) }}">Вперед</a>
        {% endif %}
    </div>
</body>
</html>
'''




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

@app.route('/pay', methods=['GET', 'POST'])
def pay():
    key = request.args.get('key', '')  # Получаем ключ из GET-параметра, если он есть

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

    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    
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
            <img src="https://cabinet.sovamonitoring.com/static/Sova_logo.jpg" alt="Логотип SOVA MONITORING" style="height: 50px;">
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
                    <a class="nav-link" href="https://sovamonitoring.com/buy">Купить устройство</a>
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
                <input type="text" id="key" name="key" value="{{ key }}" required>

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
                    <p>&copy; 2025 SOVA MONITORING. Все права защищены.</p>
                </div>
            </div>
        </div>
    </footer>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
''', key=key)



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


def notify_user_about_key_status():
    logger.info("Начало проверки сроков действия подписок для отправки уведомлений...")

    try:
        conn = sqlite3.connect('/root/miner-data/file.db')
        cursor = conn.cursor()

        current_date = datetime.now().date()

        cursor.execute("""
            SELECT k.id, k.user_id, k.key, k.end_date, u.email, u.phone_number, k.last_notification
            FROM user_keys k
            JOIN users u ON k.user_id = u.id
            WHERE k.status IN ('active', 'new', 'inactive')
        """)

        keys = cursor.fetchall()
        logger.info(f"Найдено подписок: {len(keys)} для проверки")

        if not keys:
            logger.info("Нет подписок для уведомления")
            return

        for key in keys:
            key_id = key[0]
            key_value = key[2]  # Используем key_value вместо device_id
            end_date_str = key[3]
            email = key[4]
            phone_number = key[5]
            last_notification_str = key[6]

            if not end_date_str:
                logger.warning(f"Подписка с ключом {key_value} не имеет даты окончания.")
                continue

            end_date = datetime.strptime(end_date_str, '%Y-%m-%d %H:%M:%S').date()
            remaining_days = (end_date - current_date).days

            if last_notification_str:
                last_notification = datetime.strptime(last_notification_str, '%Y-%m-%d').date()
                if last_notification == current_date:
                    logger.info(f"Подписка с ключом {key_value} проверена. Уведомление не требуется, до окончания осталось {remaining_days} дней.")
                    continue

            if remaining_days == 5:
                send_notification(key_value, email, phone_number, f"Подписка для устройства {key_value} истекает через 5 дней.", include_link=True)
                logger.info(f"Уведомление отправлено для ключа {key_value}. До окончания действия осталось 5 дней.")
            elif remaining_days == 2:
                send_notification(key_value, email, phone_number, f"Подписка для устройства {key_value} истекает через 2 дня.", include_link=False)
                logger.info(f"Уведомление отправлено для ключа {key_value}. До окончания действия осталось 2 дня.")
            elif remaining_days == 0:
                send_notification(key_value, email, phone_number, f"Подписка для устройства {key_value} истекла. Доступ приостановлен.", include_link=False)
                logger.info(f"Уведомление отправлено для ключа {key_value}. Подписка истекла сегодня.")
            else:
                logger.info(f"Подписка с ключом {key_value} проверена. Уведомление уже было отправлено сегодня.")

            cursor.execute("""
                UPDATE user_keys
                SET last_notification = ?
                WHERE id = ?
            """, (current_date, key_id))
            conn.commit()

    except Exception as e:
        logger.error(f"Ошибка при отправке уведомлений: {e}")
    finally:
        if conn:
            cursor.close()
            conn.close()

def send_notification(key_value, email, phone_number, message, include_link=False):
    logger.info(f"Отправка уведомлений для подписки устройства с уникальным номером {key_value}: {message}")

    # Отправляем SMS
    sms_message = message
    if include_link:
        sms_message += f" Продлить доступ: https://cabinet.sovamonitoring.com/pay?key={key_value}"
    
    if send_sms(phone_number, sms_message):
        logger.info(f"SMS успешно отправлено на {phone_number}")
    else:
        logger.error(f"Ошибка отправки SMS на {phone_number}")

    # Отправляем Email
    email_message = f"{message} Продлите доступ на сайте: https://cabinet.sovamonitoring.com/pay?key={key_value}"
    if send_email(email, f"Уведомление о подписке устройства {key_value}", email_message):
        logger.info(f"Email успешно отправлено на {email}")
    else:
        logger.error(f"Ошибка отправки email на {email}")


def fetch_usd_to_rub_exchange_rate():
    """Функция для получения курса обмена USD на RUB."""
    url = "https://open.er-api.com/v6/latest/USD"
    for _ in range(5):  # Пять попыток
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            rate = float(data.get("rates", {}).get("RUB", 0.0))
            return rate
        except requests.RequestException:
            time.sleep(5)  # Пауза перед повторной попыткой
    return None

def fetch_bitcoin_info():
    """Функция для получения информации о Bitcoin."""
    coin_id = '1-bitcoin-sha-256'
    url = f'https://whattomine.com/coins/{coin_id}.json'
    for _ in range(5):  # Пять попыток
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data
        except requests.RequestException:
            time.sleep(5)  # Пауза перед повторной попыткой
        except ValueError:
            return {}
    return None

def calculate_metrics_and_send():
    # Установка временной зоны Иркутска
    irkutsk_tz = pytz.timezone("Asia/Irkutsk")
    now = datetime.now(irkutsk_tz)
    one_day_ago = now - timedelta(days=1)

    # Подключение к базам данных
    activations_conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
    payments_conn = sqlite3.connect(DATABASE_PATH)

    try:
        # Подсчет активаций за последние 24 часа
        activations_cursor = activations_conn.cursor()
        activations_cursor.execute(
            """
            SELECT COUNT(*)
            FROM user_keys
            WHERE status = 'active' AND DATETIME(start_date) >= ? AND DATETIME(start_date) <= ?
            """,
            (one_day_ago.strftime('%Y-%m-%d %H:%M:%S'), now.strftime('%Y-%m-%d %H:%M:%S'))
        )
        activation_count = activations_cursor.fetchone()[0]

        # Подсчет продлений за последние 24 часа
        payments_cursor = payments_conn.cursor()
        payments_cursor.execute(
            """
            SELECT COUNT(*), SUM(amount)
            FROM payment
            WHERE processed = 1 AND DATETIME(payment_date) >= ? AND DATETIME(payment_date) <= ?
            """,
            (one_day_ago.strftime('%Y-%m-%d %H:%M:%S'), now.strftime('%Y-%m-%d %H:%M:%S'))
        )
        extensions_count, total_amount = payments_cursor.fetchone()

        # Проверка на None
        total_amount = total_amount if total_amount is not None else 0

        # Получение курса USD и Bitcoin
        usd_to_rub_rate = fetch_usd_to_rub_exchange_rate()
        bitcoin_info = fetch_bitcoin_info()
        bitcoin_price = bitcoin_info.get('exchange_rate', 'неизвестно')

        # Формирование сообщения
        message = (
            f"Здравствуйте. Роман Михайлович!\n"
            f"Отчет за последние 24 часа:\n"
            f"Количество активаций: {activation_count}\n"
            f"Количество продлений: {extensions_count}\n"
            f"Общая сумма продлений: {total_amount} руб.\n"
            f"Курс USD к RUB: {usd_to_rub_rate if usd_to_rub_rate else 'не удалось получить'}\n"
            f"Курс Bitcoin: {bitcoin_price}"
        )

        # Отправка сообщения на указанный номер
        send_sms("79086640880", message)

    except Exception as e:
        print(f"Ошибка при выполнении задачи: {e}")

    finally:
        # Закрытие соединений
        activations_conn.close()
        payments_conn.close()



if __name__ == '__main__':
    read_db_path = '/root/miner-data/file.db'
    write_db_path = '/root/cabinet/instance/metrics.db'

    # Запуск потока для периодического сохранения
    thread = threading.Thread(target=periodic_save, args=(read_db_path, write_db_path, 3600))  # Сохранение раз в час
    thread.start()

    # Инициализация и настройка фонового планировщика с указанием временной зоны
    scheduler = BackgroundScheduler(timezone=pytz.timezone('Asia/Irkutsk'))

    # Задание для отправки отчета в 10 утра
    #scheduler.add_job(calculate_metrics_and_send, 'cron', hour=10, minute=0)

    # Другие задачи
    scheduler.add_job(update_key_status, 'interval', minutes=60)
    scheduler.add_job(sync_keys, 'interval', minutes=1)
    scheduler.add_job(notify_user_about_key_status, 'cron', hour=19, minute=0)

    # Запуск планировщика
    scheduler.start()

    # Остановка планировщика при выходе
    atexit.register(lambda: scheduler.shutdown())

    # Запуск Flask-приложения
    app.run(host='0.0.0.0', port=5001)
