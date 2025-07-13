from flask import Blueprint, render_template, request, jsonify, g
from flask_login import login_required, current_user
from app.utils.decorators import auth_required, role_required
from app.services.device_service import DeviceService
import sqlite3
import json
import pandas as pd
from datetime import datetime, timedelta

devices_bp = Blueprint('devices', __name__)

@devices_bp.route('/devices', methods=['GET'])
@auth_required
@role_required('admin')
def devices_list():
    """Список всех устройств"""
    conn = sqlite3.connect('/root/websocket/secondary_data.db')
    
    try:
        # Получение данных об устройствах
        query = '''
        SELECT uk.*, u.username
        FROM user_key uk
        LEFT JOIN user u ON uk.user_id = u.id
        ORDER BY uk.start_date DESC
        '''
        
        devices_df = pd.read_sql_query(query, conn)
        
        # Подсчёт статистики
        total_devices = len(devices_df)
        active_devices = len(devices_df[devices_df['status'] == 'active'])
        inactive_devices = len(devices_df[devices_df['status'] == 'inactive'])
        
        conn.close()

        return render_template('devices/list.html',
                             devices=devices_df.to_dict('records'),
                             total_devices=total_devices,
                             active_devices=active_devices,
                             inactive_devices=inactive_devices)

    except Exception as e:
        conn.close()
        return f"Ошибка при получении данных: {e}", 500

# Удалено: функционал key_access перенесен в отдельный модуль app/key_access/

@devices_bp.route('/devices/<int:user_id>')
def devices_view(user_id):
    """Устройства конкретного пользователя"""
    conn = sqlite3.connect('/root/websocket/secondary_data.db')
    
    try:
        # Получение устройств пользователя
        query = '''
        SELECT uk.*, u.username
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
        conn = sqlite3.connect('/root/websocket/secondary_data.db')
        cursor = conn.cursor()
        
        # Получаем данные для ключа
        cursor.execute("SELECT * FROM miner_data WHERE key_uid = ?", (key,))
        data = cursor.fetchall()
        
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

def get_data_for_user(role):
    """Получение данных для пользователя в зависимости от роли"""
    # Здесь должна быть логика получения данных в зависимости от роли
    # Пока возвращаем пустые данные
    return [], pd.DataFrame(), [], pd.DataFrame(), pd.DataFrame() 