import sqlite3
import json
import pytz
from datetime import datetime
from flask import Blueprint, render_template, request, g
from app.utils.decorators import auth_required, role_required

# Пути к базам данных
DEVICES_DB_PATH = '/root/websocket/devices_data.db'
SECONDARY_DB_PATH = '/root/miner-data/file.db'

def get_device_data_by_uid(key):
    """
    Считывает запись из /root/websocket/devices_data.db по uid=key.
    Возвращает (device_info, structured_data) или (None, None).
    """
    try:
        conn = sqlite3.connect(DEVICES_DB_PATH)
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
    Извлекает из второй БД (SECONDARY_DB_PATH) все записи, где key = ?.
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
        conn = sqlite3.connect(SECONDARY_DB_PATH)
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

def calculate_time_ago(device_info):
    """Вычисляет время, прошедшее с последнего обновления устройства"""
    if not device_info:
        return None
    
    try:
        timestamp_format = "%Y-%m-%d %H:%M:%S"
        utc = pytz.utc
        timestamp = datetime.strptime(device_info['timestamp'], timestamp_format)
        timestamp = utc.localize(timestamp)

        local_timezone = pytz.timezone("Europe/Moscow")
        current_time = datetime.now(utc).astimezone(local_timezone)
        timestamp_local = timestamp.astimezone(local_timezone)
        time_difference = current_time - timestamp_local

        seconds = time_difference.total_seconds()
        if seconds < 60:
            return f"{int(seconds)} секунд назад"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            return f"{minutes} минут назад"
        else:
            hours = int(seconds // 3600)
            return f"{hours} часов назад"
    except:
        return None

def key_access_view(key):
    """Основная логика для отображения информации о ключе"""
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

    # Вычисляем "time_ago"
    time_ago = calculate_time_ago(device_info)

    return {
        'device_info': device_info,
        'structured_data': structured_data,
        'secondary_total': secondary_total,
        'offline_count': offline_count,
        'offline_ips': offline_ips,
        'device_ip_count': device_ip_count,
        'missing_on_client': missing_on_client,
        'missing_on_server': missing_on_server,
        'time_ago': time_ago
    }

# Маршруты
from app.key_access import key_access_bp

@key_access_bp.route('/key_access/<key>', methods=['GET'])
@auth_required
@role_required('admin')
def key_access(key):
    """Страница доступа к ключу"""
    # Получаем данные
    data = key_access_view(key)
    
    # Предыдущий URL
    previous_url = request.referrer if request.referrer else '/keys_management'
    
    return render_template('key_access/index.html',
                         **data,
                         previous_url=previous_url)

@key_access_bp.route('/key_access/<key>/diagnostics', methods=['GET'])
@auth_required
@role_required('admin')
def key_access_diagnostics(key):
    """Страница диагностики ключа"""
    device_info, structured_data = get_device_data_by_uid(key)
    
    # Предыдущий URL
    previous_url = request.referrer if request.referrer else f'/key_access/{key}'
    
    return render_template('key_access/diagnostics.html',
                         device_info=device_info,
                         structured_data=structured_data,
                         previous_url=previous_url) 