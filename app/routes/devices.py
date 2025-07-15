from flask import Blueprint, render_template, request, jsonify, g
from flask_login import login_required, current_user
from app.utils.decorators import auth_required, role_required
from app.services.device_service import DeviceService
import sqlite3
import json
import pandas as pd
from datetime import datetime, timedelta
import os

devices_bp = Blueprint('devices', __name__)

# Константы для путей к базам данных
SECONDARY_DATABASE_PATH = '/root/miner-data/file.db'

def get_data_for_user(role):
    """Получение данных для пользователя в зависимости от роли - скопировано из create_summary_table.py"""
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

@devices_bp.route('/devices', methods=['GET'])
@auth_required
@role_required('admin')
def devices_list():
    """
    Вывод списка устройств из device_data.db,
    при этом подтягиваем Статус ключа (колонка 'status' из user_keys),
    добавляем колонки «Устройство» и «Сервер» (число IP) с подсветкой при расхождении.
    Последовательность сохранена как исходная, 
    но «Статус ключа» поставлен перед «Устройство».
    """
    # 1. Получаем общие данные (включая user_keys) из функции
    role = g.user.role
    users, user_tariffs, tariffs, user_keys, miner_data = get_data_for_user(role)

    # 2. Создаём словарь для статусов ключей: { key_uid: status }
    key_status_map = {}
    if not user_keys.empty:
        for idx, row in user_keys.iterrows():
            key_uid = row['key']
            key_sts = row['status']
            key_status_map[key_uid] = key_sts

    devices_db_path = '/root/websocket/devices_data.db'

    try:
        conn = sqlite3.connect(devices_db_path)
        cursor = conn.cursor()

        # Получаем все строки из device_data
        cursor.execute("SELECT * FROM device_data")
        devices = cursor.fetchall()

        devices_info = []
        
        for index, device in enumerate(devices, start=1):
            # device: (id, uid, ip, port, json_data)
            uid_value = device[1]

            structured_data = None
            try:
                structured_data = json.loads(device[4])
            except (json.JSONDecodeError, TypeError):
                pass

            # Статус ключа из user_keys (или 'Неизвестно')
            key_status_value = key_status_map.get(uid_value, 'Неизвестно')

            # Данные из второй базы (miner_data) – сравниваем IP
            secondary_data = get_secondary_data_for_key(uid_value)
            secondary_ips = set(item["miner_ip"] for item in secondary_data)

            device_ips = set()
            if structured_data and "miner_info" in structured_data:
                ip_data = structured_data["miner_info"].get("ip_data", {})
                device_ips = set(ip_data.keys())

            missing_on_client = secondary_ips - device_ips
            missing_on_server = device_ips - secondary_ips

            # Количество IP на устройстве и на сервере
            device_count = len(device_ips)
            server_count = len(secondary_ips)

            # Проверяем, есть ли несоответствия (подсветка)
            any_mismatch = (len(missing_on_client) > 0) or (len(missing_on_server) > 0)

            devices_info.append({
                'number': index,
                'uid': uid_value,
                'ip': device[2],
                'port': device[3],
                'internal_ip': structured_data.get('internal_ip') if structured_data else None,
                'timestamp': structured_data.get('current_time') if (structured_data and 'current_time' in structured_data) else '',

                'distro_name': structured_data.get('distro_name') if structured_data else '',
                'distro_release': structured_data.get('distro_release') if structured_data else '',
                'kernel_version': structured_data.get('kernel_version') if structured_data else '',
                'client_version': structured_data.get('client_version') if structured_data else '',

                # Статус ключа
                'key_status': key_status_value,

                # Колонки «Устройство» / «Сервер» (числа IP)
                'device_count': device_count,
                'server_count': server_count,
                'any_mismatch': any_mismatch
            })

        conn.close()

    except Exception as e:
        return f"Error accessing device database: {e}", 500

    return render_template('devices/list.html',
                         devices_info=devices_info,
                         total_devices=len(devices_info),
                         active_devices=len([d for d in devices_info if d['key_status'] == 'active']),
                         inactive_devices=len([d for d in devices_info if d['key_status'] == 'inactive']))

# Удалено: функционал key_access перенесен в отдельный модуль app/key_access/

@devices_bp.route('/devices/<int:user_id>')
def devices_view(user_id):
    """Устройства конкретного пользователя"""
    conn = sqlite3.connect('/root/cabinet/instance/users.db')
    
    try:
        # Получение устройств пользователя - исправленный запрос
        query = '''
        SELECT uk.*, u.email, u.phone
        FROM user_key uk
        LEFT JOIN user u ON uk.user_id = u.id
        WHERE uk.user_id = ?
        ORDER BY uk.start_date DESC
        '''
        
        devices_df = pd.read_sql_query(query, conn, params=[user_id])
        conn.close()

        return render_template('devices/user_devices.html',
                             devices=devices_df.to_dict('records'),
                             user_id=user_id)

    except Exception as e:
        conn.close()
        return f"Ошибка при получении данных: {e}", 500

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
        
        if device_data:
            structured_data = None
            try:
                structured_data = json.loads(device_data[4])
            except (json.JSONDecodeError, TypeError):
                pass
            
            return device_data, structured_data
        return None, None
    except Exception:
        return None, None

def get_secondary_data_for_key(key):
    """
    Получает данные из второй базы данных для конкретного ключа
    """
    try:
        # Подключение к второй базе данных
        conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
        cursor = conn.cursor()
        
        # Получаем данные для ключа - исправлено поле key_uid на key
        cursor.execute("SELECT * FROM miner_data WHERE key = ?", (key,))
        data = cursor.fetchall()
        
        # Отладочная информация
        print(f"DEBUG: Для ключа {key} найдено {len(data)} записей в miner_data")
        
        # Преобразуем в список словарей
        columns = [description[0] for description in cursor.description]
        result = []
        for row in data:
            result.append(dict(zip(columns, row)))
        
        conn.close()
        return result
    except Exception as e:
        print(f"Error getting secondary data: {e}")
        return [] 