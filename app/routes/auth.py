from flask import Blueprint, render_template, request, redirect, url_for, flash, session, g
from app.services.auth_service import normalize_phone_number, generate_verification_code, get_user_by_phone, create_user
from app.utils.decorators import auth_required, role_required
from app.utils.helpers import send_sms
import jwt
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def home():
    """Главная страница - перенаправляет авторизованных на панель, неавторизованных на вход"""
    # Проверяем, авторизован ли пользователь
    if 'user_id' in session:
        # Если авторизован - перенаправляем на соответствующую панель
        user_role = session.get('user_role')
        if user_role == 'admin':
            return redirect(url_for('dashboard.index'))
        elif user_role == 'partner':
            return redirect(url_for('partner.dashboard'))
        elif user_role == 'manager':
            return redirect(url_for('manager.dashboard'))
        elif user_role == 'supervisor':
            return redirect(url_for('supervisor.dashboard'))
        elif user_role == 'user':
            return redirect(url_for('dashboard.index'))
        else:
            # Если роль не определена - на общий дашборд
            return redirect(url_for('dashboard.index'))
    else:
        # Если не авторизован - на страницу входа
        return redirect(url_for('auth.login'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone = request.form.get('phone')
        if phone:
            normalized_phone = normalize_phone_number(phone)
            print(f"Processing login for phone number: {normalized_phone}")
            
            user = get_user_by_phone(normalized_phone)
            if not user:
                user = create_user(normalized_phone)
            
            # Генерируем код верификации
            verification_code = generate_verification_code()
            user.verification_code = verification_code
            user.code_time = datetime.utcnow()
            
            from app import db
            db.session.commit()
            
            print(f"Generated verification code (existing user): {verification_code}")
            
            # Отправляем SMS
            message = f"{verification_code} — ваш код для входа в панель партнера Сова Мониторинг"
            send_sms(normalized_phone, message)
            print(f"SMS sent to {normalized_phone} with code {verification_code}")
            
            # Сохраняем телефон в сессии для верификации
            session['phone'] = normalized_phone
            
            return redirect(url_for('auth.verify_phone'))
    
    return render_template('auth/login.html')

@auth_bp.route('/verify-phone-number', methods=['GET', 'POST'])
def verify_phone():
    if request.method == 'POST':
        code = request.form.get('code')
        phone = session.get('phone')
        
        if phone and code:
            print(f"Verifying phone number: {phone} with code: {code}")
            
            user = get_user_by_phone(phone)
            if user and user.verification_code == code:
                print("Verification successful")
                
                # Генерируем JWT токен
                token = jwt.encode(
                    {
                        'user_id': user.id,
                        'role': user.role,
                        'exp': datetime.utcnow() + timedelta(days=365)
                    },
                    'your-secret-key-here',
                    algorithm='HS256'
                )
                print(f"Generated JWT token: {token}")
                
                # Сохраняем токен в сессии
                session['token'] = token
                session['user_id'] = user.id
                session['user_role'] = user.role
                
                # Очищаем код верификации
                user.verification_code = None
                from app import db
                db.session.commit()
                
                # Устанавливаем токен в cookies
                from flask import make_response
                response = make_response(redirect(url_for('dashboard.index')))
                response.set_cookie('token', token, httponly=True, max_age=31536000)
                return response
            else:
                flash('Неверный код подтверждения', 'error')
    
    return render_template('auth/verify.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login')) 