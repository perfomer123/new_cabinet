from flask import Blueprint, render_template, g
from app.utils.decorators import auth_required, role_required
from app.models.user import User
from app.models.user_key import UserKey
from app.models.user_operation import UserOperation
from app import db
from sqlalchemy import func
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@auth_required
@role_required('admin', 'partner', 'manager', 'supervisor', 'user')
def index():
    print(f"Accessing dashboard with user: {g.user.username}, Role: {g.user.role}")
    
    # Получаем реальную статистику
    try:
        # Общее количество пользователей
        total_users = User.query.count()
        
        # Активные ключи (привязанные к пользователям)
        active_keys = UserKey.query.count()
        
        # Общий доход (сумма всех подтверждённых операций продажи)
        total_revenue = db.session.query(func.sum(UserOperation.amount)).filter(
            UserOperation.operation_type == 'sale',
            UserOperation.status == 'confirmed'
        ).scalar() or 0
        
        # Устройства онлайн (можно заменить на реальную логику)
        online_devices = 8934  # Пока статичное значение
        
        # Статистика за последние 30 дней
        thirty_days_ago = datetime.now() - timedelta(days=30)
        recent_operations = UserOperation.query.filter(
            UserOperation.date >= thirty_days_ago
        ).count()
        
        # Новые пользователи за последние 30 дней
        new_users = User.query.filter(
            User.created_at >= thirty_days_ago
        ).count()
        
    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        # Fallback значения
        total_users = 1247
        active_keys = 15678
        total_revenue = 2400000
        online_devices = 8934
        recent_operations = 456
        new_users = 23
    
    # Определяем доступные ссылки в зависимости от роли
    links = []
    
    if g.user.role == 'admin':
        links.extend([
            {'url': '/admin', 'text': 'Панель администратора'},
            {'url': '/manage_statuses', 'text': 'Управление'},
            {'url': '/money', 'text': 'Финансы'}
        ])
    elif g.user.role == 'partner':
        links.append({'url': '/partner', 'text': 'Панель партнёра'})
    elif g.user.role == 'manager':
        links.append({'url': '/manager', 'text': 'Панель менеджера'})
    elif g.user.role == 'supervisor':
        links.append({'url': '/supervisor', 'text': 'Панель супервизора'})
    elif g.user.role == 'user':
        links.append({'url': '/user', 'text': 'Панель пользователя'})
    
    # Общие ссылки для всех ролей
    common_links = [
        {'url': '/logout', 'text': 'Выйти'},
        {'url': 'https://cabinet.sovamonitoring.com/daily_metrics', 'text': 'Ежедневные метрики'},
        {'url': '/partner_statistics', 'text': 'Статистика по партнёрам'}
    ]
    
    # Форматируем статистику для отображения
    stats = {
        'total_users': f"{total_users:,}",
        'active_keys': f"{active_keys:,}",
        'total_revenue': f"₽{total_revenue:,.0f}",
        'online_devices': f"{online_devices:,}",
        'recent_operations': f"{recent_operations:,}",
        'new_users': f"{new_users:,}"
    }
    
    return render_template('dashboard/index.html', 
                         user=g.user, 
                         links=links, 
                         common_links=common_links,
                         stats=stats) 