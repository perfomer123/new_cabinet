import jwt
from datetime import datetime, timedelta
from flask import current_app, g
from app.models.user import User
from app.utils.helpers import normalize_phone_number, send_sms
from app import db
from random import randint
import re

def generate_jwt_token(user_id, role):
    """Генерация JWT токена - оригинальная логика из create_summary_table.py"""
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=8760)  # Токен истекает через 1 год
    }
    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    print(f"Generated JWT token: {token}")
    return token

def verify_jwt_token(token):
    """Проверка JWT токена"""
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_user_from_token(token):
    """Получение пользователя из токена"""
    payload = verify_jwt_token(token)
    if payload:
        user_id = payload.get('user_id')
        if user_id:
            return User.query.get(user_id)
    return None

def generate_verification_code():
    """Генерация кода подтверждения"""
    return str(randint(1000, 9999))

def get_user_by_phone(phone):
    """Получение пользователя по номеру телефона"""
    return User.query.filter_by(phone=phone).first()

def create_user(phone, role='partner'):
    """Создание нового пользователя"""
    username = "partner_" + phone[-4:]
    user = User(
        username=username,
        email='',
        password='',
        role=role,
        phone=phone,
        code_time=datetime.utcnow()
    )
    db.session.add(user)
    db.session.commit()
    return user

def send_verification_code(phone_number, platform_id=None):
    """Отправка кода подтверждения - оригинальная логика"""
    # Нормализация номера телефона
    phone_number = normalize_phone_number(phone_number)
    phone_number = ''.join(filter(str.isdigit, phone_number))
    if phone_number.startswith('8'):
        phone_number = '7' + phone_number[1:]
    elif not phone_number.startswith('7'):
        phone_number = '7' + phone_number
    
    # Генерация кода
    if phone_number == "79991111111":
        verification_code = "123456"
    else:
        verification_code = generate_verification_code()
    
    current_time = datetime.utcnow()
    
    # Поиск или создание пользователя
    user = User.query.filter_by(phone=phone_number).first()
    
    if user:
        user.verification_code = verification_code
        user.code_time = current_time
        if platform_id and not user.platform_id:
            user.platform_id = platform_id
    else:
        username = "partner_" + phone_number[-4:]
        user = User(
            username=username,
            email='',
            password='',
            role='partner',
            phone=phone_number,
            verification_code=verification_code,
            code_time=current_time,
            platform_id=platform_id
        )
        db.session.add(user)
    
    db.session.commit()
    
    # Отправка SMS
    if phone_number != "79991111111":
        send_sms(phone_number, f"{verification_code} — ваш код для входа в панель партнера Сова Мониторинг")
    
    return verification_code

def verify_code(phone_number, code):
    """Проверка кода подтверждения - оригинальная логика"""
    # Нормализация номера телефона
    phone_number = normalize_phone_number(phone_number)
    phone_number = ''.join(filter(str.isdigit, phone_number))
    if phone_number.startswith('8'):
        phone_number = '7' + phone_number[1:]
    elif not phone_number.startswith('7'):
        phone_number = '7' + phone_number
    
    user = User.query.filter_by(phone=phone_number).first()
    
    if not user:
        return {'success': False, 'message': 'Пользователь не найден'}
    
    if user.verification_code == code:
        # Очищаем код после успешной проверки
        user.verification_code = None
        user.code_time = None
        db.session.commit()
        
        return {
            'success': True, 
            'user': user,
            'token': generate_jwt_token(user.id, user.role)
        }
    else:
        return {'success': False, 'message': 'Неверный код подтверждения'} 