from flask import Blueprint, render_template, request, jsonify
from app.utils.decorators import auth_required, role_required
import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any

partner_statistics_bp = Blueprint('partner_statistics', __name__)

def convert_numpy_types(obj: Any) -> Any:
    """Конвертирует numpy типы в стандартные Python типы для JSON сериализации"""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    return obj

def get_default_date_range() -> Tuple[str, str]:
    """Возвращает диапазон дат по умолчанию (последние 7 дней)"""
    today_date = datetime.now().date()
    end_date = today_date.isoformat()
    start_date = (today_date - timedelta(days=6)).isoformat()
    return start_date, end_date

def parse_date(date_str):
    """Преобразует дату из d.m.Y или Y-m-d в isoformat (YYYY-MM-DD)"""
    for fmt in ("%d.%m.%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str, fmt).date().isoformat()
        except Exception:
            continue
    return date_str  # если не удалось преобразовать, вернуть как есть

def get_partner_statistics_data(start_date: str, end_date: str, selected_partners: List[str]) -> Dict[str, Any]:
    """
    Получает данные статистики партнеров из базы данных
    
    Args:
        start_date: Дата начала периода
        end_date: Дата окончания периода  
        selected_partners: Список выбранных партнеров
        
    Returns:
        Словарь с данными статистики
    """
    conn = sqlite3.connect('instance/users.db')
    
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
        
        if not stats_period.empty:
            stats_period['activation_date'] = pd.to_datetime(stats_period['activation_date']).dt.strftime('%d.%m.%y')
            stats_period['activated_devices'] = stats_period['activated_devices'].astype(int)
        
        # Все партнёры за период
        partners = stats_period['partner_name'].unique().tolist() if not stats_period.empty else []
        
        # Если не выбрано — все
        if not selected_partners or 'all' in selected_partners:
            selected_partners = partners
        
        # Фильтрация по выбранным
        stats_period = stats_period[stats_period['partner_name'].isin(selected_partners)]
        
        # Подсчёт статистики за период
        period_stats = {}
        period_total = 0
        for partner in selected_partners:
            df_partner = stats_period[stats_period['partner_name'] == partner]
            period_total_partner = int(df_partner['activated_devices'].sum()) if not df_partner.empty else 0
            period_stats[partner] = period_total_partner
            period_total += period_total_partner
        
        period_percent = {p: (period_stats[p] / period_total * 100 if period_total else 0) for p in selected_partners}
        
        # Статистика за сегодня
        today_date = datetime.now().date()
        today_str = today_date.strftime('%Y-%m-%d')
        query_today = '''
        SELECT u.username AS partner_name,
               COUNT(k.id) AS activated_devices
        FROM user_key k
        LEFT JOIN user u ON k.user_id = u.id
        WHERE k.status IN ('active', 'inactive')
          AND DATE(k.start_date) = ?
        GROUP BY u.username
        ORDER BY u.username
        '''
        
        stats_today = pd.read_sql_query(query_today, conn, params=[today_str])
        if not stats_today.empty:
            stats_today['activated_devices'] = stats_today['activated_devices'].astype(int)
        
        stats_today = stats_today[stats_today['partner_name'].isin(selected_partners)]
        
        today_stats = {}
        today_total = 0
        for partner in selected_partners:
            row = stats_today[stats_today['partner_name'] == partner]
            count = int(row['activated_devices'].sum()) if not row.empty else 0
            today_stats[partner] = count
            today_total += count
        
        today_percent = {p: (today_stats[p] / today_total * 100 if today_total else 0) for p in selected_partners}
        
        # Детали по дням
        partner_details = {}
        for partner in selected_partners:
            df_partner = stats_period[stats_period['partner_name'] == partner]
            details = (df_partner[['activation_date', 'activated_devices']]
                       .drop_duplicates().to_dict('records')
                       if not df_partner.empty else [])
            for detail in details:
                detail['activated_devices'] = int(detail['activated_devices'])
            partner_details[partner] = details
        
        return {
            'partners': partners,
            'selected_partners': selected_partners,
            'period_stats': convert_numpy_types(period_stats),
            'period_percent': convert_numpy_types(period_percent),
            'period_total': period_total,
            'today_stats': convert_numpy_types(today_stats),
            'today_percent': convert_numpy_types(today_percent),
            'today_total': today_total,
            'partner_details': convert_numpy_types(partner_details),
            'start_date': start_date,
            'end_date': end_date
        }
        
    except Exception as e:
        raise Exception(f"Ошибка при получении данных из базы: {str(e)}")
    finally:
        conn.close()

@partner_statistics_bp.route('/partner_statistics')
@auth_required
@role_required('admin')
def partner_statistics():
    """Основная страница статистики партнеров"""
    try:
        # Получение параметров запроса
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        selected_partners = request.args.getlist('partner')
        
        # Установка значений по умолчанию
        if not start_date or not end_date:
            start_date, end_date = get_default_date_range()
        
        # Преобразуем даты, если они в формате d.m.Y
        if start_date:
            start_date = parse_date(start_date)
        if end_date:
            end_date = parse_date(end_date)
        
        # Получение данных
        data = get_partner_statistics_data(start_date, end_date, selected_partners)
        
        return render_template('partner_statistics/index.html', **data)
        
    except Exception as e:
        print(f"Error in partner_statistics: {e}")
        return render_template('partner_statistics/index.html', 
                             error=str(e),
                             partners=[],
                             selected_partners=[],
                             period_stats={},
                             period_percent={},
                             period_total=0,
                             today_stats={},
                             today_percent={},
                             today_total=0,
                             partner_details={},
                             start_date=start_date if 'start_date' in locals() else '',
                             end_date=end_date if 'end_date' in locals() else '')

@partner_statistics_bp.route('/api/partner_statistics')
@auth_required
@role_required('admin')
def api_partner_statistics():
    """API endpoint для AJAX запросов статистики партнеров"""
    try:
        # Получение параметров запроса
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        selected_partners = request.args.getlist('partner')
        
        # Установка значений по умолчанию
        if not start_date or not end_date:
            start_date, end_date = get_default_date_range()
        
        # Преобразуем даты, если они в формате d.m.Y
        if start_date:
            start_date = parse_date(start_date)
        if end_date:
            end_date = parse_date(end_date)
        
        # Получение данных
        data = get_partner_statistics_data(start_date, end_date, selected_partners)
        
        # Добавляем дополнительные данные для AJAX
        data['all_partners'] = data['partners']
        data['selected_partners'] = selected_partners if selected_partners else ['all']
        
        return jsonify(data)
        
    except Exception as e:
        print(f"Error in api_partner_statistics: {e}")
        return jsonify({'error': str(e)}), 500

@partner_statistics_bp.route('/partner_statistics/all_time')
@auth_required
@role_required('admin')
def partner_statistics_all_time():
    """Страница статистики партнеров за все время"""
    conn = sqlite3.connect('instance/users.db')
    
    try:
        # Запрос для получения общей статистики "за всё время"
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
        
        return render_template('partner_statistics/all_time.html',
                             partners=partners,
                             total_all_time=total_all_time,
                             overall_total_footer=overall_total_footer)
                             
    except Exception as e:
        print(f"Error in partner_statistics_all_time: {e}")
        return render_template('partner_statistics/all_time.html',
                             error=str(e),
                             partners=[],
                             total_all_time={},
                             overall_total_footer=0)
    finally:
        conn.close() 