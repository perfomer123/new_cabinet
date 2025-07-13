from flask import Blueprint, render_template, g
from app.utils.decorators import auth_required, role_required

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@auth_required
@role_required('admin', 'partner', 'manager', 'supervisor', 'user')
def index():
    print(f"Accessing dashboard with user: {g.user.username}, Role: {g.user.role}")
    
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
    
    return render_template('dashboard/index.html', user=g.user, links=links, common_links=common_links) 