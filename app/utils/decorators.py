from functools import wraps
from flask import request, redirect, url_for, flash, g, current_app
from app.services.auth_service import verify_jwt_token, get_user_from_token
from app.models.user import User

def auth_required(f):
    """Декоратор для проверки аутентификации"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Проверяем токен из cookies
        token = request.cookies.get('token')
        
        if not token:
            flash('Необходима авторизация', 'error')
            return redirect(url_for('auth.login'))
        
        # Проверяем токен
        payload = verify_jwt_token(token)
        if not payload:
            flash('Сессия истекла. Войдите снова', 'error')
            return redirect(url_for('auth.login'))
        
        # Получаем пользователя
        user = User.query.get(payload.get('user_id'))
        if not user:
            flash('Пользователь не найден', 'error')
            return redirect(url_for('auth.login'))
        
        # Сохраняем пользователя в g для использования в представлениях
        g.user = user
        return f(*args, **kwargs)
    
    return decorated_function

def role_required(*roles):
    """Декоратор для проверки роли пользователя"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Сначала проверяем аутентификацию
            token = request.cookies.get('token')
            
            if not token:
                flash('Необходима авторизация', 'error')
                return redirect(url_for('auth.login'))
            
            payload = verify_jwt_token(token)
            if not payload:
                flash('Сессия истекла. Войдите снова', 'error')
                return redirect(url_for('auth.login'))
            
            user = User.query.get(payload.get('user_id'))
            if not user:
                flash('Пользователь не найден', 'error')
                return redirect(url_for('auth.login'))
            
            # Проверяем роль
            if user.role not in roles:
                flash('Недостаточно прав для доступа к этой странице', 'error')
                return redirect(url_for('dashboard.index'))
            
            g.user = user
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator 

def admin_only(f):
    """Декоратор для роутов, доступных только администраторам"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Сначала проверяем аутентификацию
        token = request.cookies.get('token')
        
        if not token:
            flash('Необходима авторизация', 'error')
            return redirect(url_for('auth.login'))
        
        payload = verify_jwt_token(token)
        if not payload:
            flash('Сессия истекла. Войдите снова', 'error')
            return redirect(url_for('auth.login'))
        
        user = User.query.get(payload.get('user_id'))
        if not user:
            flash('Пользователь не найден', 'error')
            return redirect(url_for('auth.login'))
        
        # Проверяем, что это админ
        if user.role != 'admin':
            flash('Доступ запрещен. Только администраторы могут использовать эту функцию.', 'error')
            return redirect(url_for('dashboard.index'))
        
        g.user = user
        return f(*args, **kwargs)
    
    return decorated_function 