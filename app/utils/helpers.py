from datetime import datetime, timedelta
import requests
from random import randint
import re
import pandas as pd
import os
import sqlite3

def calculate_days_left(end_date):
    if not end_date:
        return 0
    try:
        if isinstance(end_date, str):
            end = datetime.strptime(end_date, '%Y-%m-%d %H:%M:%S')
        else:
            end = end_date
        delta = end - datetime.now()
        return max(delta.days, 0)
    except Exception:
        return 0

def format_date(dt):
    if not dt:
        return ''
    if isinstance(dt, str):
        return dt
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def normalize_phone_number(phone_number):
    """Нормализация номера телефона"""
    if not phone_number:
        return None
    
    # Удаляем все символы кроме цифр
    digits_only = re.sub(r'\D', '', phone_number)
    
    # Если номер начинается с 8, заменяем на 7
    if digits_only.startswith('8'):
        digits_only = '7' + digits_only[1:]
    
    # Если номер начинается с +7, убираем +
    if digits_only.startswith('+7'):
        digits_only = '7' + digits_only[2:]
    
    # Если номер начинается с 7 и имеет 11 цифр, возвращаем как есть
    if digits_only.startswith('7') and len(digits_only) == 11:
        return digits_only
    
    # Если номер имеет 10 цифр и начинается с 9, добавляем 7
    if len(digits_only) == 10 and digits_only.startswith('9'):
        return '7' + digits_only
    
    return digits_only

def parse_date(date_str):
    """Парсинг даты из строки"""
    if not date_str or date_str == 'N/A':
        return None
    try:
        return pd.to_datetime(date_str)
    except:
        return None

def send_sms(phone_number, message):
    """Отправка SMS через phone_utils.py"""
    try:
        from phone_utils import send_sms as send_sms_original
        return send_sms_original(phone_number, message)
    except ImportError:
        # Fallback если phone_utils.py недоступен
        print(f"SMS to {phone_number}: {message}")
        return True
    except Exception as e:
        print(f"Error sending SMS: {e}")
        return False

def calculate_new_end_date(current_end_date, extension_days):
    if current_end_date:
        end_date = datetime.strptime(current_end_date, '%Y-%m-%d %H:%M:%S')
    else:
        end_date = datetime.now()
    start_date = max(datetime.now(), end_date)
    new_end_date = start_date + timedelta(days=extension_days)
    return new_end_date

def extend_key_subscription(user_id, tariff_id, amount, extension_days, key):
    conn = sqlite3.connect("/root/miner-data/file.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_keys WHERE key=?", (key,))
    user_key = cursor.fetchone()
    if not user_key:
        return {"status": False, "message": "Key not found"}, 404
    # Индексы: 0-id, 1-user_id, 2-key, 3-key_name, 4-status, 5-start_date, 6-end_date, 7-tariff_id
    new_end_date = calculate_new_end_date(user_key[6], extension_days)
    new_status = "active"
    new_key_name = user_key[3].replace("(OFF) ", "") if user_key[3] and user_key[3].startswith("(OFF)") else user_key[3]
    cursor.execute("UPDATE user_keys SET end_date=?, status=?, key_name=? WHERE key=?", (new_end_date.strftime("%Y-%m-%d %H:%M:%S"), new_status, new_key_name, key))
    conn.commit()
    cursor.execute("SELECT status, key_name FROM user_keys WHERE key=?", (key,))
    updated_status, updated_key_name = cursor.fetchone()
    conn.close()
    return {"status": True, "new_subscription_end_date": new_end_date.strftime("%Y-%m-%d %H:%M:%S")}, 200

# Константы из оригинального кода
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATABASE_PATH = '/root/cabinet/instance/users.db'
SECONDARY_DATABASE_PATH = '/root/miner-data/file.db'

# Подключение к базе данных и получение данных в зависимости от роли пользователя
def get_data_for_user(role):
    conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
    if role == 'admin':
        users = pd.read_sql_query("SELECT id, email, phone_number, password, telegram_id FROM users", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data", conn)
    elif role == 'partner':
        users = pd.read_sql_query("SELECT id, email, phone_number, password, telegram_id FROM users WHERE role = 'partner'", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs WHERE user_id IN (SELECT id FROM users WHERE role = 'partner')", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys WHERE user_id IN (SELECT id FROM users WHERE role = 'partner')", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data WHERE user_id IN (SELECT id FROM users WHERE role = 'partner')", conn)
    elif role == 'manager':
        users = pd.read_sql_query("SELECT id, email, phone_number, password, telegram_id FROM users WHERE role = 'manager'", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs WHERE user_id IN (SELECT id FROM users WHERE role = 'manager')", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys WHERE user_id IN (SELECT id FROM users WHERE role = 'manager')", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data WHERE user_id IN (SELECT id FROM users WHERE role = 'manager')", conn)
    else:
        users = pd.read_sql_query("SELECT id, email, phone_number, password, telegram_id FROM users", conn)
        user_tariffs = pd.read_sql_query("SELECT user_id, tariff_id, start_date, end_date FROM user_tariffs", conn)
        tariffs = pd.read_sql_query("SELECT id AS tariff_id, name FROM tariffs", conn)
        user_keys = pd.read_sql_query("SELECT user_id, key, key_name, status, start_date, end_date, tariff_id FROM user_keys", conn)
        miner_data = pd.read_sql_query(
            "SELECT user_id, key, miner_ip, device_model, mhs_av, hs_rt, temperature, fan_speed_in, fan_speed_out, power, uptime_hours, uptime_minutes, power_mode, power_limit, pool_url, pool_user, status "
            "FROM miner_data", conn)

    conn.close()
    return users, user_tariffs, tariffs, user_keys, miner_data 