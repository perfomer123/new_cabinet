from app import db
from app.models import User, UserKey, Tariff, Earning
from datetime import datetime
import random

def normalize_phone_number(phone_number):
    phone = ''.join(filter(str.isdigit, phone_number))
    if phone.startswith('8'):
        phone = '7' + phone[1:]
    if not phone.startswith('7'):
        phone = '7' + phone
    return phone

def generate_verification_code():
    return str(random.randint(1000, 9999))

def get_user_by_phone(phone):
    return User.query.filter_by(phone=phone).first()

def get_user_by_id(user_id):
    return User.query.get(user_id)

def create_user(phone, role='user'):
    user = User(phone=phone, role=role, username=phone, code_time=datetime.utcnow())
    db.session.add(user)
    db.session.commit()
    return user 

def get_user_data(user_id):
    """Получение всех данных пользователя"""
    
    # Ключи пользователя
    user_keys = (db.session.query(UserKey, User)
                  .join(User, UserKey.user_id == User.id)
                  .filter(User.id == user_id)
                  .all())

    total_new_devices = sum(1 for key, _ in user_keys if key.status == 'new')
    total_active_devices = sum(1 for key, _ in user_keys if key.status == 'active')

    # Тарифы
    main_tariff = Tariff.query.get(User.query.get(user_id).tariff_id) if User.query.get(user_id).tariff_id else None
    tariff_ids = {key.tariff_id for key, _ in user_keys if key.tariff_id}
    key_tariffs = Tariff.query.filter(Tariff.id.in_(tariff_ids)).all() if tariff_ids else []
    assigned_tariffs = ([main_tariff] if main_tariff else []) + key_tariffs

    # Финансы
    earnings_data = Earning.query.filter_by(user_id=user_id).all()
    earnings_summary = sum(e.amount for e in earnings_data)

    return {
        'user_keys': user_keys,
        'total_new_devices': total_new_devices,
        'total_active_devices': total_active_devices,
        'assigned_tariffs': assigned_tariffs,
        'earnings_data': earnings_data,
        'earnings_summary': earnings_summary
    }

def calculate_days_left(end_date):
    """Расчет оставшихся дней"""
    if not end_date:
        return ''
    if isinstance(end_date, datetime):
        return (end_date - datetime.now()).days
    try:
        dt = datetime.strptime(str(end_date), '%Y-%m-%d %H:%M:%S')
        return (dt - datetime.now()).days
    except Exception:
        return '' 