import pandas as pd
from flask import render_template, jsonify, request, g, session, redirect, url_for
from functools import wraps
from . import keys_management
from app.models.user import User
from app.models.user_key import UserKey
from app.models.tariff import Tariff
from .utils import get_data_for_user, process_keys_data, get_paginated_keys_data, clear_cache, get_keys_statistics, get_universal_search_data

# Декоратор для проверки аутентификации
def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

# Декоратор для проверки роли
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('auth.login'))
            
            # Получаем пользователя из базы данных
            user = User.query.get(session['user_id'])
            if not user or user.role not in roles:
                return redirect(url_for('auth.login'))
            
            g.user = user
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@keys_management.route('/api/keys_management', methods=['GET'])
@auth_required
@role_required('admin')
def api_keys_management():
    """API для получения данных управления ключами"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    filters = {
        'email': request.args.get('email', '', type=str),
        'phone_number': request.args.get('phone_number', '', type=str),
        'key': request.args.get('key', '', type=str),
        'key_name': request.args.get('key_name', '', type=str),
        'start_date': request.args.get('start_date', '', type=str),
        'end_date': request.args.get('end_date', '', type=str),
        'status': request.args.get('status', '', type=str),
        'tariff': request.args.get('tariff', '', type=str)
    }

    role = g.user.role
    users, user_tariffs, tariffs, user_keys, miner_data = get_data_for_user(role)

    user_keys_with_tariffs = user_keys.merge(
        tariffs,
        on='tariff_id',
        how='left'
    )

    merged_data = users.merge(
        user_keys_with_tariffs,
        left_on='id',
        right_on='user_id',
        how='left'
    ).fillna('N/A')

    # Найдём идентификаторы клиентов, которые совпадают по фильтру
    matching_users = merged_data.copy()
    for key, value in filters.items():
        if value:
            matching_users = matching_users[matching_users[key].str.contains(value, case=False, na=False)]

    matching_ids = matching_users['id'].unique()

    # Отбираем ВСЕ записи для найденных клиентов
    filtered_data = merged_data[merged_data['id'].isin(matching_ids)]

    total_users = len(filtered_data['id'].unique())
    user_ids_paginated = filtered_data['id'].unique()[(page-1)*per_page:page*per_page]
    filtered_data = filtered_data[filtered_data['id'].isin(user_ids_paginated)]

    result = filtered_data[[
        'id', 'email', 'phone_number', 'key', 'key_name',
        'start_date', 'end_date', 'status', 'name'
    ]].to_dict(orient='records')

    return jsonify({'data': result, 'total': total_users})

@keys_management.route('/keys_management', methods=['GET'])
@auth_required
@role_required('admin')
def keys_management_view():
    """Главная страница управления ключами с поиском"""
    role = g.user.role
    search_query = request.args.get('q', '', type=str)
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    user_keys_dict = None
    total = page_num = per_page_num = total_pages = None
    if search_query.strip():
        result = get_universal_search_data(role, page, per_page, search_query)
        user_keys_dict = result['data']
        total = result['total']
        page_num = result['page']
        per_page_num = result['per_page']
        total_pages = result['total_pages']
    return render_template('keys_management/dashboard.html',
        search_query=search_query,
        user_keys_dict=user_keys_dict,
        total=total,
        page=page_num,
        per_page=per_page_num,
        total_pages=total_pages,
        role=role
    )

@keys_management.route('/keys_management/search', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def keys_search_view():
    """Страница универсального поиска ключей"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search_query = request.args.get('q', '', type=str)

    role = g.user.role
    
    # Используем универсальный поиск
    result = get_universal_search_data(role, page, per_page, search_query)
    
    return render_template('keys_management/search.html', 
                         user_keys_dict=result['data'],
                         total=result['total'],
                         page=result['page'],
                         per_page=result['per_page'],
                         total_pages=result['total_pages'],
                         search_query=search_query)

@keys_management.route('/keys_management/clear_cache', methods=['POST'])
@auth_required
@role_required('admin')
def clear_keys_cache():
    """Очистка кэша данных"""
    clear_cache()
    return jsonify({'success': True, 'message': 'Кэш очищен'}) 