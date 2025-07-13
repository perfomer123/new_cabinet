from flask import Blueprint, render_template, request, jsonify, g
from flask_login import login_required, current_user
from app.utils.decorators import auth_required, role_required
from app.services.report_service import ReportService
from app import db
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import json
import math

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/daily_metrics')
@auth_required
@role_required('admin')
def daily_metrics():
    """Ежедневные метрики"""
    conn_main = get_db_connection()  # Подключение к основной базе
    conn_secondary = sqlite3.connect('/root/websocket/secondary_data.db')  # Подключение к базе с user_keys

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

    return render_template('reports/daily_metrics.html', metrics=metrics)





@reports_bp.route('/money')
@auth_required
@role_required('admin')
def money_table():
    """Таблица денежных операций"""
    import sqlite3
    import pandas as pd
    from sqlalchemy import and_, func
    
    # --- Чтение GET-параметров ---
    sort_by = request.args.get('sort_by', 'payment_date')
    order = request.args.get('order', 'desc')
    processed_filter = request.args.get('processed', None)

    # Автоматический выбор последней недели по умолчанию
    today = datetime.today()
    default_start = (today - timedelta(days=7)).strftime('%Y-%m-%d')
    default_end = today.strftime('%Y-%m-%d')

    start_date = request.args.get('start_date', default_start)
    end_date = request.args.get('end_date', default_end)

    # Преобразуем даты к формату с временем
    start_datetime = f"{start_date} 00:00:00"
    end_datetime = f"{end_date} 23:59:59"

    # Вычисляем предыдущий период (такой же длительности)
    start_dt = datetime.strptime(start_date, '%Y-%m-%d')
    end_dt = datetime.strptime(end_date, '%Y-%m-%d')
    period_days = (end_dt - start_dt).days + 1
    
    previous_end_dt = start_dt - timedelta(days=1)
    previous_start_dt = previous_end_dt - timedelta(days=period_days-1)
    
    previous_start_date = previous_start_dt.strftime('%Y-%m-%d')
    previous_end_date = previous_end_dt.strftime('%Y-%m-%d')
    previous_start_datetime = f"{previous_start_date} 00:00:00"
    previous_end_datetime = f"{previous_end_date} 23:59:59"

    # --- Читаем платежи из базы данных users.db ---
    conn_payments = sqlite3.connect('instance/users.db')
    conn_payments.row_factory = sqlite3.Row
    
    try:
        # --- Формируем WHERE-условие и параметры для текущего периода ---
        where_clauses = ["payment_date BETWEEN ? AND ?"]
        params = [start_datetime, end_datetime]

        if processed_filter in ['Да', 'Нет']:
            where_clauses.append("processed = ?")
            params.append(1 if processed_filter == 'Да' else 0)

        where_clause = 'WHERE ' + ' AND '.join(where_clauses)

        # --- Блок статистики для текущего периода ---
        query_stats = f'''
        SELECT amount, processed 
        FROM payment
        {where_clause}
        '''
        df_stats = pd.read_sql_query(query_stats, conn_payments, params=params)

        if not df_stats.empty:
            total_amount = df_stats['amount'].sum()
            average_amount = df_stats['amount'].mean()
            processed_payments = df_stats[df_stats['processed'] == 1]['amount'].sum()
            unprocessed_payments = df_stats[df_stats['processed'] == 0]['amount'].sum()
            payment_count = len(df_stats)
        else:
            total_amount = 0
            average_amount = 0
            processed_payments = 0
            unprocessed_payments = 0
            payment_count = 0

        # --- Блок статистики для предыдущего периода ---
        where_clauses_prev = ["payment_date BETWEEN ? AND ?"]
        params_prev = [previous_start_datetime, previous_end_datetime]

        if processed_filter in ['Да', 'Нет']:
            where_clauses_prev.append("processed = ?")
            params_prev.append(1 if processed_filter == 'Да' else 0)

        where_clause_prev = 'WHERE ' + ' AND '.join(where_clauses_prev)

        query_stats_prev = f'''
        SELECT amount, processed 
        FROM payment
        {where_clause_prev}
        '''
        df_stats_prev = pd.read_sql_query(query_stats_prev, conn_payments, params=params_prev)

        if not df_stats_prev.empty:
            total_amount_prev = df_stats_prev['amount'].sum()
            average_amount_prev = df_stats_prev['amount'].mean()
            processed_payments_prev = df_stats_prev[df_stats_prev['processed'] == 1]['amount'].sum()
            payment_count_prev = len(df_stats_prev)
        else:
            total_amount_prev = 0
            average_amount_prev = 0
            processed_payments_prev = 0
            payment_count_prev = 0

        # --- Вычисляем процентные изменения ---
        def calculate_percentage_change(current, previous):
            if previous == 0:
                return 100 if current > 0 else 0
            return round(((current - previous) / previous) * 100, 1)

        payment_count_change = calculate_percentage_change(payment_count, payment_count_prev)
        total_amount_change = calculate_percentage_change(total_amount, total_amount_prev)
        average_amount_change = calculate_percentage_change(average_amount, average_amount_prev)
        processed_payments_change = calculate_percentage_change(processed_payments, processed_payments_prev)

        # --- Блок формирования данных для графика (сумма по дням) ---
        query_graph = f'''
        SELECT date(payment_date) AS payment_date, SUM(amount) AS amount
        FROM payment
        {where_clause}
        GROUP BY date(payment_date)
        ORDER BY date(payment_date)
        '''
        df_graph = pd.read_sql_query(query_graph, conn_payments, params=params)
        if df_graph.empty:
            dates = []
            amounts = []
        else:
            dates = df_graph['payment_date'].astype(str).tolist()
            amounts = df_graph['amount'].tolist()

        # --- Пагинация ---
        page = request.args.get('page', 1, type=int)
        per_page = 20
        offset = (page - 1) * per_page

        params_paginated = params + [per_page, offset]

        # Определяем порядок сортировки
        sort_order = 'ASC' if order == 'asc' else 'DESC'
        
        # --- Основной запрос с пагинацией ---
        query_payments = f'''
        SELECT 
            user_id, 
            tariff_id, 
            amount, 
            extension_days, 
            payment_date, 
            key, 
            payment_id, 
            processed
        FROM payment
        {where_clause}
        ORDER BY {sort_by} {sort_order}
        LIMIT ? OFFSET ?
        '''

        df_payments = pd.read_sql_query(query_payments, conn_payments, params=params_paginated)
        df_payments['payment_date'] = pd.to_datetime(df_payments['payment_date']).dt.date

        # Подсчитываем общее число записей (без учёта LIMIT)
        total_records_query = f'SELECT COUNT(*) FROM payment {where_clause}'
        total_records = conn_payments.execute(total_records_query, params).fetchone()[0]
        total_pages = math.ceil(total_records / per_page)

    finally:
        conn_payments.close()

    # --- Загружаем пользователей из второй БД, чтобы получить email/phone_number/telegram_id ---
    conn_users = sqlite3.connect('/root/miner-data/file.db')
    conn_users.row_factory = sqlite3.Row
    try:
        df_users = pd.read_sql_query("SELECT id, email, phone_number, telegram_id FROM users", conn_users)
    finally:
        conn_users.close()

    # --- Объединяем платежи с пользователями по user_id ---
    df_merged = pd.merge(df_payments, df_users, left_on='user_id', right_on='id', how='left')
    df_merged = df_merged.fillna('')  # Заменяем NaN на пустую строку
    if 'telegram_id' in df_merged.columns:
        df_merged['telegram_id'] = df_merged['telegram_id'].astype(str)

    # Формируем идентификатор и тип контакта для каждого пользователя
    def get_identifier_and_type(row):
        if row['email'] and row['email'] != '':
            return row['email'], 'email'
        elif row['phone_number'] and row['phone_number'] != '':
            return row['phone_number'], 'phone'
        elif row['telegram_id'] and row['telegram_id'] != '':
            return row['telegram_id'], 'telegram'
        else:
            return None, None
    
    # Применяем функцию к каждой строке
    identifiers_and_types = df_merged.apply(get_identifier_and_type, axis=1)
    df_merged['identifier'] = [item[0] for item in identifiers_and_types]
    df_merged['contact_type'] = [item[1] for item in identifiers_and_types]

    # Подготовим финальные данные для шаблона
    data = df_merged.to_dict(orient='records')
    
    # Проверяем, является ли это AJAX-запросом
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Генерируем HTML для таблицы
        table_html = ''
        for row in data:
            contact_html = ''
            if row['contact_type'] == 'email':
                contact_html = f'<i class="fas fa-envelope text-primary contact-icon"></i><span>{row["identifier"]}</span>'
            elif row['contact_type'] == 'phone':
                contact_html = f'<i class="fas fa-phone text-success contact-icon"></i><span>{row["identifier"]}</span>'
            elif row['contact_type'] == 'telegram':
                contact_html = f'<i class="fab fa-telegram text-info contact-icon"></i><span>{row["identifier"]}</span>'
            else:
                contact_html = '<i class="fa-solid fa-question text-muted contact-icon"></i><span class="text-muted">Нет контакта</span>'
            
            user_html = ''
            if row['identifier']:
                user_html = f'<a href="/client/{row["identifier"]}" class="text-decoration-none"><i class="fa-solid fa-user me-1"></i>{row["user_id"]}</a>'
            else:
                user_html = f'<i class="fa-solid fa-user me-1"></i>{row["user_id"]}'
            
            key_html = ''
            if row['identifier']:
                key_html = f'<a href="/client/{row["identifier"]}" class="text-decoration-none"><code>{row["key"]}</code></a>'
            else:
                key_html = f'<code>{row["key"]}</code>'
            
            status_html = ''
            if row['processed']:
                status_html = '<span class="badge bg-success"><i class="fa-solid fa-check me-1"></i>Обработан</span>'
            else:
                status_html = '<span class="badge bg-warning"><i class="fa-solid fa-clock me-1"></i>В ожидании</span>'
            
            table_html += f'''
            <tr>
                <td>{user_html}</td>
                <td>{contact_html}</td>
                <td><span class="badge bg-secondary">{row["tariff_id"]}</span></td>
                <td><strong>{row["amount"]} ₽</strong></td>
                <td><span class="badge bg-info">{row["extension_days"]} дн.</span></td>
                <td>{row["payment_date"]}</td>
                <td>{key_html}</td>
                <td><code>{row["payment_id"]}</code></td>
                <td>{status_html}</td>
            </tr>
            '''
        
        # Генерируем HTML для пагинации
        pagination_html = ''
        if total_pages > 1:
            pagination_html = '<nav><ul class="pagination justify-content-center">'
            
            if page > 1:
                pagination_html += f'''
                <li class="page-item">
                    <a class="page-link" href="#" onclick="loadPage({page-1})">
                        <i class="fa-solid fa-chevron-left me-1"></i>Назад
                    </a>
                </li>
                '''
            
            for p in range(1, total_pages+1):
                active_class = 'active' if p == page else ''
                pagination_html += f'<li class="page-item {active_class}"><a class="page-link" href="#" onclick="loadPage({p})">{p}</a></li>'
            
            if page < total_pages:
                pagination_html += f'''
                <li class="page-item">
                    <a class="page-link" href="#" onclick="loadPage({page+1})">
                        Вперед<i class="fa-solid fa-chevron-right ms-1"></i>
                    </a>
                </li>
                '''
            
            pagination_html += '</ul></nav>'
        
        return jsonify({
            'stats': {
                'payment_count': payment_count,
                'total_amount': total_amount,
                'average_amount': round(average_amount, 2),
                'processed_payments': processed_payments,
                'unprocessed_payments': unprocessed_payments,
                'payment_count_change': payment_count_change,
                'total_amount_change': total_amount_change,
                'average_amount_change': average_amount_change,
                'processed_payments_change': processed_payments_change
            },
            'charts': {
                'dates': dates,
                'amounts': amounts,
                'processedPayments': processed_payments,
                'unprocessedPayments': unprocessed_payments
            },
            'table': table_html,
            'pagination': pagination_html,
            'comparison': {
                'current_period': f"{start_date} - {end_date}",
                'previous_period': f"{previous_start_date} - {previous_end_date}"
            }
        })

    # Обычный запрос - возвращаем полную страницу
    return render_template('reports/money_table.html',
                         data=data,
                         page=page,
                         total_pages=total_pages,
                         sort_by=sort_by,
                         order=order,
                         processed_filter=processed_filter,
                         start_date=start_date,
                         end_date=end_date,
                         previous_start_date=previous_start_date,
                         previous_end_date=previous_end_date,
                         total_amount=total_amount,
                         average_amount=average_amount,
                         processed_payments=processed_payments,
                         unprocessed_payments=unprocessed_payments,
                         payment_count=payment_count,
                         payment_count_change=payment_count_change,
                         total_amount_change=total_amount_change,
                         average_amount_change=average_amount_change,
                         processed_payments_change=processed_payments_change,
                         dates=dates,
                         amounts=amounts)

def get_db_connection():
    """Получение подключения к основной базе данных"""
    return sqlite3.connect('/root/websocket/devices_data.db') 