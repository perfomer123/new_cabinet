import sqlite3
import pandas as pd
from datetime import datetime
import time

# Путь к вторичной базе данных
SECONDARY_DATABASE_PATH = '/root/miner-data/file.db'

# Кэш для данных (в продакшене лучше использовать Redis)
_data_cache = {}
_cache_timestamp = {}

def get_data_for_user(role):
    """Получение данных для пользователя в зависимости от роли"""
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

def get_paginated_keys_data(role, page=1, per_page=50, filters=None):
    """Оптимизированное получение данных с пагинацией на уровне базы данных"""
    if filters is None:
        filters = {}
    
    cache_key = f"{role}_{page}_{per_page}_{hash(str(filters))}"
    current_time = time.time()
    
    # Проверяем кэш (кэш на 5 минут)
    if cache_key in _data_cache and (current_time - _cache_timestamp.get(cache_key, 0)) < 300:
        return _data_cache[cache_key]
    
    conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
    
    # Базовые запросы с LIMIT и OFFSET
    offset = (page - 1) * per_page
    
    # Строим WHERE условия для фильтров
    where_conditions = []
    params = []
    
    if role != 'admin':
        where_conditions.append("u.role = ?")
        params.append(role)
    
    # Добавляем фильтры
    if filters.get('email'):
        where_conditions.append("u.email LIKE ?")
        params.append(f"%{filters['email']}%")
    
    if filters.get('phone_number'):
        where_conditions.append("u.phone_number LIKE ?")
        params.append(f"%{filters['phone_number']}%")
    
    if filters.get('key'):
        where_conditions.append("uk.key LIKE ?")
        params.append(f"%{filters['key']}%")
    
    if filters.get('key_name'):
        where_conditions.append("uk.key_name LIKE ?")
        params.append(f"%{filters['key_name']}%")
    
    if filters.get('status'):
        where_conditions.append("uk.status LIKE ?")
        params.append(f"%{filters['status']}%")
    
    if filters.get('tariff'):
        where_conditions.append("t.name LIKE ?")
        params.append(f"%{filters['tariff']}%")
    
    if filters.get('start_date'):
        where_conditions.append("uk.start_date LIKE ?")
        params.append(f"%{filters['start_date']}%")
    
    if filters.get('end_date'):
        where_conditions.append("uk.end_date LIKE ?")
        params.append(f"%{filters['end_date']}%")
    
    # Формируем WHERE часть запроса
    where_clause = ""
    if where_conditions:
        where_clause = "WHERE " + " AND ".join(where_conditions)
    
    if role == 'admin':
        # Получаем общее количество пользователей с фильтрами
        total_query = f"""
        SELECT COUNT(DISTINCT u.id) as total 
        FROM users u
        LEFT JOIN user_keys uk ON u.id = uk.user_id
        LEFT JOIN tariffs t ON uk.tariff_id = t.id
        {where_clause}
        """
        total_result = pd.read_sql_query(total_query, conn, params=params)
        total = total_result['total'].iloc[0]
        
        # Основной запрос с пагинацией и фильтрами
        main_query = f"""
        SELECT DISTINCT u.id, u.email, u.phone_number, u.telegram_id,
               uk.key, uk.key_name, uk.status, uk.start_date, uk.end_date,
               t.name as tariff_name
        FROM users u
        LEFT JOIN user_keys uk ON u.id = uk.user_id
        LEFT JOIN tariffs t ON uk.tariff_id = t.id
        {where_clause}
        ORDER BY u.id
        LIMIT ? OFFSET ?
        """
        
        data = pd.read_sql_query(main_query, conn, params=params + [per_page, offset])
        
    else:
        # Для других ролей добавляем фильтр по роли
        total_query = f"""
        SELECT COUNT(DISTINCT u.id) as total 
        FROM users u
        LEFT JOIN user_keys uk ON u.id = uk.user_id
        LEFT JOIN tariffs t ON uk.tariff_id = t.id
        {where_clause}
        """
        total_result = pd.read_sql_query(total_query, conn, params=params)
        total = total_result['total'].iloc[0]
        
        main_query = f"""
        SELECT DISTINCT u.id, u.email, u.phone_number, u.telegram_id,
               uk.key, uk.key_name, uk.status, uk.start_date, uk.end_date,
               t.name as tariff_name
        FROM users u
        LEFT JOIN user_keys uk ON u.id = uk.user_id
        LEFT JOIN tariffs t ON uk.tariff_id = t.id
        {where_clause}
        ORDER BY u.id
        LIMIT ? OFFSET ?
        """
        
        data = pd.read_sql_query(main_query, conn, params=params + [per_page, offset])
    
    conn.close()
    
    # Обработка данных
    processed_data = process_paginated_data(data)
    
    # Сохраняем в кэш
    result = {
        'data': processed_data,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page if total > 0 else 0
    }
    
    _data_cache[cache_key] = result
    _cache_timestamp[cache_key] = current_time
    
    return result

def get_universal_search_data(role, page=1, per_page=50, search_query=None):
    """Универсальный поиск по всем полям"""
    if search_query is None:
        search_query = ""
    
    print(f"DEBUG: Поиск по запросу '{search_query}' для роли '{role}'")
    
    cache_key = f"{role}_{page}_{per_page}_search_{hash(search_query)}"
    current_time = time.time()
    
    # Проверяем кэш (кэш на 5 минут)
    if cache_key in _data_cache and (current_time - _cache_timestamp.get(cache_key, 0)) < 300:
        print(f"DEBUG: Возвращаем результат из кэша")
        return _data_cache[cache_key]
    
    conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
    
    def unicode_lower(s):
        if s is None:
            return ''
        return str(s).lower()
    conn.create_function("PY_LOWER", 1, unicode_lower)

    # Базовые запросы с LIMIT и OFFSET
    offset = (page - 1) * per_page
    
    # Строим WHERE условия для поиска
    where_conditions = []
    params = []
    
    if role != 'admin':
        where_conditions.append("u.role = ?")
        params.append(role)
    
    # Универсальный поиск по всем полям (без учета регистра)
    if search_query.strip():
        search_condition = """
        (PY_LOWER(u.email) LIKE PY_LOWER(?) OR PY_LOWER(u.phone_number) LIKE PY_LOWER(?) OR PY_LOWER(u.telegram_id) LIKE PY_LOWER(?) OR 
        PY_LOWER(uk.key) LIKE PY_LOWER(?) OR PY_LOWER(uk.key_name) LIKE PY_LOWER(?) OR PY_LOWER(uk.status) LIKE PY_LOWER(?) OR 
        PY_LOWER(t.name) LIKE PY_LOWER(?) OR PY_LOWER(uk.start_date) LIKE PY_LOWER(?) OR PY_LOWER(uk.end_date) LIKE PY_LOWER(?))
        """
        search_param = f"%{search_query}%"
        params.extend([search_param] * 9)  # 9 параметров для поиска
        where_conditions.append(search_condition)
        print(f"DEBUG: Добавлен поисковый запрос с параметром '{search_param}' (PY_LOWER, поддержка кириллицы)")
    
    # Формируем WHERE часть запроса
    where_clause = ""
    if where_conditions:
        where_clause = "WHERE " + " AND ".join(where_conditions)
    
    print(f"DEBUG: WHERE clause: {where_clause}")
    print(f"DEBUG: Параметры: {params}")
    
    if role == 'admin':
        # Получаем общее количество пользователей с поиском
        total_query = f"""
        SELECT COUNT(DISTINCT u.id) as total 
        FROM users u
        LEFT JOIN user_keys uk ON u.id = uk.user_id
        LEFT JOIN tariffs t ON uk.tariff_id = t.id
        {where_clause}
        """
        total_result = pd.read_sql_query(total_query, conn, params=params)
        total = total_result['total'].iloc[0]
        
        # Основной запрос с пагинацией и поиском (все связанные записи)
        main_query = f"""
        SELECT u.id, u.email, u.phone_number, u.telegram_id,
               uk.key, uk.key_name, uk.status, uk.start_date, uk.end_date,
               t.name as tariff_name
        FROM users u
        LEFT JOIN user_keys uk ON u.id = uk.user_id
        LEFT JOIN tariffs t ON uk.tariff_id = t.id
        {where_clause}
        ORDER BY u.id, uk.id
        LIMIT ? OFFSET ?
        """
        
        data = pd.read_sql_query(main_query, conn, params=params + [per_page, offset])
        
    else:
        # Для других ролей добавляем фильтр по роли
        total_query = f"""
        SELECT COUNT(DISTINCT u.id) as total 
        FROM users u
        LEFT JOIN user_keys uk ON u.id = uk.user_id
        LEFT JOIN tariffs t ON uk.tariff_id = t.id
        {where_clause}
        """
        total_result = pd.read_sql_query(total_query, conn, params=params)
        total = total_result['total'].iloc[0]
        
        main_query = f"""
        SELECT u.id, u.email, u.phone_number, u.telegram_id,
               uk.key, uk.key_name, uk.status, uk.start_date, uk.end_date,
               t.name as tariff_name
        FROM users u
        LEFT JOIN user_keys uk ON u.id = uk.user_id
        LEFT JOIN tariffs t ON uk.tariff_id = t.id
        {where_clause}
        ORDER BY u.id, uk.id
        LIMIT ? OFFSET ?
        """
        
        data = pd.read_sql_query(main_query, conn, params=params + [per_page, offset])
    
    conn.close()
    
    # Обработка данных
    processed_data = process_paginated_data(data)
    
    # Сохраняем в кэш
    result = {
        'data': processed_data,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page if total > 0 else 0
    }
    
    _data_cache[cache_key] = result
    _cache_timestamp[cache_key] = current_time
    
    return result

def process_paginated_data(data):
    """Обработка пагинированных данных"""
    if data.empty:
        return {}
    
    # Заполнение пропущенных значений
    data['email'].fillna('', inplace=True)
    data['phone_number'].fillna('', inplace=True)
    data['telegram_id'].fillna('', inplace=True)
    data['key_name'].fillna('Без названия', inplace=True)
    data['start_date'].fillna('N/A', inplace=True)
    data['end_date'].fillna('N/A', inplace=True)
    data['status'].fillna('N/A', inplace=True)
    data['tariff_name'].fillna('Без тарифа', inplace=True)
    
    # Форматирование дат
    data['start_date'] = data['start_date'].apply(format_date)
    data['end_date'] = data['end_date'].apply(format_date)
    
    # Создание идентификатора пользователя
    data['identifier'] = data.apply(get_identifier, axis=1)
    
    # Группировка по пользователям
    user_keys_dict = {}
    for identifier, group in data.groupby('identifier'):
        user_info = group.iloc[0]
        user_keys_dict[identifier] = {
            'email': user_info['email'] if user_info['email'] else 'Нет почты',
            'phone_number': user_info['phone_number'] if user_info['phone_number'] else 'Нет телефона',
            'telegram_id': user_info['telegram_id'] if user_info['telegram_id'] else 'Нет Telegram',
            'user_keys': group[['key', 'key_name', 'start_date', 'end_date', 'status', 'tariff_name']].rename(columns={'key': 'key_value', 'tariff_name': 'name'}).to_dict(orient='records')
        }
    
    return user_keys_dict

def clear_cache():
    """Очистка кэша"""
    global _data_cache, _cache_timestamp
    _data_cache.clear()
    _cache_timestamp.clear()

def format_date(x):
    """Форматирование даты для отображения"""
    if x != 'N/A':
        try:
            return pd.to_datetime(x).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return x
    else:
        return x

def get_identifier(row):
    """Создание идентификатора пользователя для входа"""
    if row['telegram_id']:
        return row['telegram_id'].replace('@', '')
    elif row['email']:
        return row['email']
    elif row['phone_number']:
        return row['phone_number']
    else:
        return 'user_{}'.format(row['id'])

def process_keys_data(merged_data):
    """Обработка данных ключей для отображения"""
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

    # Форматирование дат
    merged_data['start_date'] = merged_data['start_date'].apply(format_date)
    merged_data['end_date'] = merged_data['end_date'].apply(format_date)

    # Создание идентификатора пользователя
    merged_data['identifier'] = merged_data.apply(get_identifier, axis=1)

    # Преобразование данных в словарь
    user_keys_dict = {}
    for identifier, group in merged_data.groupby('identifier'):
        user_info = group.iloc[0]
        user_keys_dict[identifier] = {
            'email': user_info['email'] if user_info['email'] else 'Нет почты',
            'phone_number': user_info['phone_number'] if user_info['phone_number'] else 'Нет телефона',
            'user_keys': group[['key', 'key_name', 'start_date', 'end_date', 'status', 'name']].rename(columns={'key': 'key_value'}).to_dict(orient='records')
        }

    return user_keys_dict 

def get_keys_statistics(role):
    """Получение статистики по ключам"""
    conn = sqlite3.connect(SECONDARY_DATABASE_PATH)
    
    if role == 'admin':
        # Общая статистика
        total_users_query = "SELECT COUNT(DISTINCT id) as total FROM users"
        total_keys_query = "SELECT COUNT(*) as total FROM user_keys"
        active_keys_query = "SELECT COUNT(*) as total FROM user_keys WHERE status = 'active'"
        pending_keys_query = "SELECT COUNT(*) as total FROM user_keys WHERE status = 'pending'"
        expired_keys_query = "SELECT COUNT(*) as total FROM user_keys WHERE status = 'expired'"
        
        # Статистика по тарифам
        tariff_stats_query = """
        SELECT t.name, COUNT(uk.id) as count
        FROM tariffs t
        LEFT JOIN user_keys uk ON t.id = uk.tariff_id
        GROUP BY t.id, t.name
        ORDER BY count DESC
        """
        
        # Статистика по статусам
        status_stats_query = """
        SELECT status, COUNT(*) as count
        FROM user_keys
        GROUP BY status
        ORDER BY count DESC
        """
        
    else:
        # Статистика для конкретной роли
        total_users_query = "SELECT COUNT(DISTINCT id) as total FROM users WHERE role = ?"
        total_keys_query = """
        SELECT COUNT(*) as total 
        FROM user_keys uk
        JOIN users u ON uk.user_id = u.id
        WHERE u.role = ?
        """
        active_keys_query = """
        SELECT COUNT(*) as total 
        FROM user_keys uk
        JOIN users u ON uk.user_id = u.id
        WHERE u.role = ? AND uk.status = 'active'
        """
        pending_keys_query = """
        SELECT COUNT(*) as total 
        FROM user_keys uk
        JOIN users u ON uk.user_id = u.id
        WHERE u.role = ? AND uk.status = 'pending'
        """
        expired_keys_query = """
        SELECT COUNT(*) as total 
        FROM user_keys uk
        JOIN users u ON uk.user_id = u.id
        WHERE u.role = ? AND uk.status = 'expired'
        """
        
        # Статистика по тарифам для роли
        tariff_stats_query = """
        SELECT t.name, COUNT(uk.id) as count
        FROM tariffs t
        LEFT JOIN user_keys uk ON t.id = uk.tariff_id
        LEFT JOIN users u ON uk.user_id = u.id
        WHERE u.role = ?
        GROUP BY t.id, t.name
        ORDER BY count DESC
        """
        
        # Статистика по статусам для роли
        status_stats_query = """
        SELECT uk.status, COUNT(*) as count
        FROM user_keys uk
        JOIN users u ON uk.user_id = u.id
        WHERE u.role = ?
        GROUP BY uk.status
        ORDER BY count DESC
        """
    
    # Выполняем запросы
    if role == 'admin':
        total_users = pd.read_sql_query(total_users_query, conn)['total'].iloc[0]
        total_keys = pd.read_sql_query(total_keys_query, conn)['total'].iloc[0]
        active_keys = pd.read_sql_query(active_keys_query, conn)['total'].iloc[0]
        pending_keys = pd.read_sql_query(pending_keys_query, conn)['total'].iloc[0]
        expired_keys = pd.read_sql_query(expired_keys_query, conn)['total'].iloc[0]
        tariff_stats = pd.read_sql_query(tariff_stats_query, conn)
        status_stats = pd.read_sql_query(status_stats_query, conn)
    else:
        total_users = pd.read_sql_query(total_users_query, conn, params=[role])['total'].iloc[0]
        total_keys = pd.read_sql_query(total_keys_query, conn, params=[role])['total'].iloc[0]
        active_keys = pd.read_sql_query(active_keys_query, conn, params=[role])['total'].iloc[0]
        pending_keys = pd.read_sql_query(pending_keys_query, conn, params=[role])['total'].iloc[0]
        expired_keys = pd.read_sql_query(expired_keys_query, conn, params=[role])['total'].iloc[0]
        tariff_stats = pd.read_sql_query(tariff_stats_query, conn, params=[role])
        status_stats = pd.read_sql_query(status_stats_query, conn, params=[role])
    
    conn.close()
    
    return {
        'total_users': total_users,
        'total_keys': total_keys,
        'active_keys': active_keys,
        'pending_keys': pending_keys,
        'expired_keys': expired_keys,
        'tariff_stats': tariff_stats.to_dict('records'),
        'status_stats': status_stats.to_dict('records')
    } 