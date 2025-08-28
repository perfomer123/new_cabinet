from flask import Blueprint, render_template, request, redirect, url_for, flash, g, jsonify
from app.utils.decorators import auth_required, role_required, admin_only
from app.models.user import User
from app.models.tariff import Tariff
from app.models.payment import Payment
from app.models.user_key import UserKey
from app.models.user_operation import UserOperation
from app.models.support_ticket import SupportTicket
from app.models.support_message import SupportMessage
from app import db
from datetime import datetime
import pandas as pd
import sqlite3
from collections import Counter

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin')
@auth_required
@role_required('admin')
def dashboard():
    """Админская панель"""
    # Получаем статистику
    total_users = User.query.count()
    total_tariffs = Tariff.query.count()
    total_payments = Payment.query.count()
    total_keys = UserKey.query.count()
    
    # Последние пользователи
    recent_users = User.query.order_by(User.id.desc()).limit(5).all()
    
    # Последние платежи
    recent_payments = Payment.query.order_by(Payment.payment_date.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_tariffs=total_tariffs,
                         total_payments=total_payments,
                         total_keys=total_keys,
                         recent_users=recent_users,
                         recent_payments=recent_payments)

@admin_bp.route('/users')
@auth_required
@role_required('admin')
def list_users():
    """Список всех пользователей"""
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/create_user', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def create_user():
    """Создание нового пользователя"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        phone = request.form.get('phone')
        
        # Проверяем, что пользователь не существует
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'error')
            return render_template('admin/create_user.html')
        
        if email and User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует', 'error')
            return render_template('admin/create_user.html')
        
        # Создаем нового пользователя
        new_user = User(
            username=username,
            email=email,
            password=password,
            role=role,
            phone=phone
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Пользователь успешно создан', 'success')
            return redirect(url_for('admin.list_users'))
        except Exception as e:
            db.session.rollback()
            flash(f"Ошибка при создании пользователя: {str(e)}", "error")
    return render_template('admin/create_user.html')

@admin_bp.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def edit_user(user_id):
    """Редактирование пользователя"""
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.role = request.form.get('role')
        user.phone = request.form.get('phone')
        
        # Если указан новый пароль
        new_password = request.form.get('password')
        if new_password:
            user.password = new_password
        
        try:
            db.session.commit()
            flash('Пользователь успешно обновлен', 'success')
            return redirect(url_for('admin.list_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при обновлении пользователя: {str(e)}', 'error')
    
    return render_template('admin/edit_user.html', user=user)

@admin_bp.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def delete_user(user_id):
    """Удаление пользователя"""
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        try:
            # Удаляем связанные операции
            UserOperation.query.filter_by(user_id=user_id).delete()
            
            # Удаляем связанные ключи
            UserKey.query.filter_by(user_id=user_id).delete()
            
            # Удаляем пользователя
            db.session.delete(user)
            db.session.commit()
            
            flash('Пользователь успешно удален', 'success')
            return redirect(url_for('admin.list_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при удалении пользователя: {str(e)}', 'error')
    
    return render_template('admin/delete_user.html', user=user)

@admin_bp.route('/tariffs')
@auth_required
@role_required('admin')
def list_tariffs():
    """Список всех тарифов"""
    tariffs = Tariff.query.all()
    return render_template('admin/tariffs.html', tariffs=tariffs)

@admin_bp.route('/create_tariff', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def create_tariff():
    """Создание нового тарифа"""
    if request.method == 'POST':
        name = request.form.get('name')
        base_price = float(request.form.get('base_price', 0))
        partner_initial_payment = float(request.form.get('partner_initial_payment', 0))
        manager_initial_payment = float(request.form.get('manager_initial_payment', 0))
        supervisor_initial_payment = float(request.form.get('supervisor_initial_payment', 0))
        partner_subscription_percentage = float(request.form.get('partner_subscription_percentage', 0))
        manager_subscription_percentage = float(request.form.get('manager_subscription_percentage', 0))
        supervisor_subscription_percentage = float(request.form.get('supervisor_subscription_percentage', 0))
        restricted = bool(request.form.get('restricted'))
        
        new_tariff = Tariff(
            name=name,
            base_price=base_price,
            partner_initial_payment=partner_initial_payment,
            manager_initial_payment=manager_initial_payment,
            supervisor_initial_payment=supervisor_initial_payment,
            partner_subscription_percentage=partner_subscription_percentage,
            manager_subscription_percentage=manager_subscription_percentage,
            supervisor_subscription_percentage=supervisor_subscription_percentage,
            restricted=restricted
        )
        
        try:
            db.session.add(new_tariff)
            db.session.commit()
            flash('Тариф успешно создан', 'success')
            return redirect(url_for('admin.list_tariffs'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при создании тарифа: {str(e)}', 'error')
    
    return render_template('admin/create_tariff.html')

@admin_bp.route('/edit_tariff/<int:tariff_id>', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def edit_tariff(tariff_id):
    """Редактирование тарифа"""
    tariff = Tariff.query.get_or_404(tariff_id)
    
    if request.method == 'POST':
        tariff.name = request.form.get('name')
        tariff.base_price = float(request.form.get('base_price', 0))
        tariff.partner_initial_payment = float(request.form.get('partner_initial_payment', 0))
        tariff.manager_initial_payment = float(request.form.get('manager_initial_payment', 0))
        tariff.supervisor_initial_payment = float(request.form.get('supervisor_initial_payment', 0))
        tariff.partner_subscription_percentage = float(request.form.get('partner_subscription_percentage', 0))
        tariff.manager_subscription_percentage = float(request.form.get('manager_subscription_percentage', 0))
        tariff.supervisor_subscription_percentage = float(request.form.get('supervisor_subscription_percentage', 0))
        tariff.restricted = bool(request.form.get('restricted'))
        
        try:
            db.session.commit()
            flash('Тариф успешно обновлен', 'success')
            return redirect(url_for('admin.list_tariffs'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при обновлении тарифа: {str(e)}', 'error')
    
    return render_template('admin/edit_tariff.html', tariff=tariff)

@admin_bp.route('/delete_tariff/<int:tariff_id>', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def delete_tariff(tariff_id):
    """Удаление тарифа"""
    tariff = Tariff.query.get_or_404(tariff_id)
    
    if request.method == 'POST':
        try:
            db.session.delete(tariff)
            db.session.commit()
            flash('Тариф успешно удален', 'success')
            return redirect(url_for('admin.list_tariffs'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при удалении тарифа: {str(e)}', 'error')
    
    return render_template('admin/delete_tariff.html', tariff=tariff)

@admin_bp.route('/manage_statuses', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def manage_statuses():
    """Управление статусами ключей"""
    if request.method == 'POST':
        # Логика обновления статусов
        flash('Статусы обновлены', 'success')
        return redirect(url_for('admin.manage_statuses'))
    
    return render_template('admin/manage_statuses.html') 

@admin_bp.route('/user/<int:user_id>/manage_keys', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def manage_keys(user_id):
    """Управление ключами пользователя"""
    user = User.query.get_or_404(user_id)
    
    # Получение всех ключей из вторичной базы данных (перемещаем в начало)
    try:
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Подключение к базе данных /root/miner-data/file.db")
        
        conn = sqlite3.connect('/root/miner-data/file.db', timeout=30.0)
        cursor = conn.cursor()
        
        logger.info("Выполнение запроса к таблице user_keys")
        cursor.execute("""
            SELECT key, status, start_date, end_date, tariff_id 
            FROM user_keys
        """)
        
        rows = cursor.fetchall()
        logger.info(f"Получено {len(rows)} записей из таблицы user_keys")
        
        all_keys = [
            {
                'key': row[0],
                'status': row[1],
                'start_date': row[2],
                'end_date': row[3],
                'tariff_id': row[4],
            }
            for row in rows
        ]
        conn.close()
        logger.info("Соединение с базой данных закрыто")
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Ошибка при получении ключей: {str(e)}", exc_info=True)
        all_keys = []
        flash(f'Ошибка при получении ключей: {str(e)}', 'error')
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_keys':
            new_keys = request.form.getlist('new_keys')
            operation_type = request.form.get('operation_type')
            amount = float(request.form.get('amount', 0))
            
            if new_keys:
                # Добавляем ключи
                for key_value in new_keys:
                    # Проверяем, что ключ не привязан к другому пользователю
                    existing_key = UserKey.query.filter_by(key=key_value).first()
                    if existing_key:
                        flash(f'Ключ {key_value} уже привязан к другому пользователю', 'error')
                        continue
                    
                    # Находим оригинальный ключ в базе данных для получения статуса
                    original_key_data = None
                    for key_data in all_keys:
                        if key_data['key'] == key_value:
                            original_key_data = key_data
                            break
                    
                    # Создаем новый ключ с оригинальным статусом
                    user_key = UserKey(
                        user_id=user_id,
                        key=key_value,
                        status=original_key_data['status'] if original_key_data else 'available',
                        start_date=original_key_data['start_date'] if original_key_data else None,
                        end_date=original_key_data['end_date'] if original_key_data else None,
                        tariff_id=original_key_data['tariff_id'] if original_key_data else None
                    )
                    db.session.add(user_key)
                
                db.session.commit()
                
                # Создаем операции для добавленных ключей
                for key_value in new_keys:
                    user_key = UserKey.query.filter_by(user_id=user_id, key=key_value).first()
                    if user_key:
                        operation = UserOperation(
                            user_id=user_id,
                            operation_type=operation_type,
                            product_id=user_key.id,
                            amount=amount,
                            status='confirmed'
                        )
                        db.session.add(operation)
                
                db.session.commit()
                flash('Ключи успешно добавлены', 'success')
            else:
                flash('Не выбрано ни одного ключа для добавления', 'warning')
                
        elif action == 'add_manual_key':
            manual_key = request.form.get('manual_key')
            if manual_key:
                # Проверяем, что ключ не привязан к другому пользователю
                existing_key = UserKey.query.filter_by(key=manual_key).first()
                if existing_key:
                    flash(f'Ключ {manual_key} уже привязан к другому пользователю', 'error')
                else:
                    # Находим оригинальный ключ в базе данных для получения статуса
                    original_key_data = None
                    for key_data in all_keys:
                        if key_data['key'] == manual_key:
                            original_key_data = key_data
                            break
                    
                    user_key = UserKey(
                        user_id=user_id,
                        key=manual_key,
                        status=original_key_data['status'] if original_key_data else 'available',
                        start_date=original_key_data['start_date'] if original_key_data else None,
                        end_date=original_key_data['end_date'] if original_key_data else None,
                        tariff_id=original_key_data['tariff_id'] if original_key_data else None
                    )
                    db.session.add(user_key)
                    db.session.commit()
                    flash('Ключ успешно добавлен вручную', 'success')
            else:
                flash('Введите корректный ключ для добавления вручную', 'warning')
                
        elif action == 'detach_keys':
            keys_to_detach = request.form.getlist('detach_keys')
            if keys_to_detach:
                # Получаем объекты ключей перед удалением
                user_keys = UserKey.query.filter_by(user_id=user_id).filter(UserKey.key.in_(keys_to_detach)).all()
                key_ids = [user_key.id for user_key in user_keys]
                
                # Удаляем операции
                for key_id in key_ids:
                    operations = UserOperation.query.filter_by(user_id=user_id, product_id=key_id).all()
                    for operation in operations:
                        # Если операция типа 'sale' и статус 'confirmed', вычитаем сумму из баланса
                        if operation.operation_type == 'sale' and operation.status == 'confirmed':
                            user.balance -= operation.amount
                        db.session.delete(operation)
                
                # Удаляем ключи
                for user_key in user_keys:
                    db.session.delete(user_key)
                
                db.session.commit()
                flash('Ключи успешно удалены', 'success')
            else:
                flash('Не выбрано ни одного ключа для удаления', 'warning')
        
        return redirect(url_for('admin.manage_keys', user_id=user_id))
    
    # Получение ключей, которые уже привязаны к пользователям
    assigned_keys = UserKey.query.with_entities(UserKey.key).all()
    assigned_key_values = set([key[0] for key in assigned_keys])
    
    # Доступные ключи - это все ключи, не привязанные к пользователям
    available_keys = [key for key in all_keys if key['key'] not in assigned_key_values]
    
    # Получение ключей, привязанных к текущему пользователю, с операциями
    user_keys = UserKey.query.filter_by(user_id=user_id).all()
    processed_user_keys = []
    
    for key in user_keys:
        days_left = 'N/A'
        if key.end_date:
            try:
                days_left = (datetime.strptime(key.end_date, '%Y-%m-%d %H:%M:%S') - datetime.now()).days
            except ValueError:
                days_left = 'Ошибка в формате даты'
        
        # Получение соответствующей операции
        operation = UserOperation.query.filter_by(user_id=user_id, product_id=key.id).first()
        if operation:
            operation_data = {
                'operation_id': operation.id,
                'operation_type': operation.operation_type,
                'amount': operation.amount,
                'status': operation.status,
                'date': operation.date.strftime('%Y-%m-%d %H:%M:%S')
            }
        else:
            operation_data = {
                'operation_id': None,
                'operation_type': '',
                'amount': '',
                'status': '',
                'date': ''
            }
        
        processed_user_keys.append({
            'id': key.id,
            'key': key.key,
            'status': key.status,
            'start_date': key.start_date,
            'end_date': key.end_date,
            'days_left': days_left,
            'tariff_id': key.tariff_id,
            'operation': operation_data
        })
    
    return render_template('admin/manage_keys.html',
                         user=user,
                         available_keys=available_keys,
                         processed_user_keys=processed_user_keys)

@admin_bp.route('/update_operation_field', methods=['POST'])
@auth_required
@role_required('admin')
def update_operation_field():
    """Обновление полей операции через AJAX"""
    try:
        operation_id = request.form.get('operation_id')
        field_name = request.form.get('field_name')
        new_value = request.form.get('new_value')
        user_id = request.form.get('user_id')
        key_id = request.form.get('key_id')
        
        if operation_id == 'new':
            # Создаем новую операцию
            operation = UserOperation(
                user_id=user_id,
                operation_type='sale' if field_name == 'operation_type' else '',
                product_id=key_id,
                amount=0.0 if field_name == 'amount' else 0.0,
                status='pending' if field_name == 'status' else 'pending'
            )
            db.session.add(operation)
            db.session.commit()
            operation_id = operation.id
        else:
            operation = UserOperation.query.get(operation_id)
            if not operation:
                return jsonify({'success': False, 'message': 'Операция не найдена'})
        
        # Обновляем поле
        if field_name == 'operation_type':
            operation.operation_type = new_value
        elif field_name == 'amount':
            operation.amount = float(new_value)
        elif field_name == 'status':
            operation.status = new_value
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'operation_id': operation.id if operation_id == 'new' else None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/user_summary/<int:user_id>')
@auth_required
@role_required('admin', 'partner', 'manager', 'supervisor', 'user')
def user_summary(user_id):
    """Профиль пользователя"""
    user = User.query.get_or_404(user_id)
    
    # Получаем все ключи, связанные с пользователем
    user_keys = UserKey.query.filter_by(user_id=user_id).all()
    total_keys = len(user_keys)
    
    # Подсчитываем количество ключей по статусам
    status_counts = Counter(key.status for key in user_keys)
    
    # Количество ключей на реализации (операции типа 'consignment')
    consignment_keys_ids = [op.product_id for op in UserOperation.query.filter_by(
        user_id=user_id,
        operation_type='consignment'
    ).all()]
    consignment_keys_count = len(consignment_keys_ids)
    
    # Количество проданных ключей (операции типа 'sale' со статусом 'confirmed')
    sold_keys_ids = [op.product_id for op in UserOperation.query.filter_by(
        user_id=user_id,
        operation_type='sale',
        status='confirmed'
    ).all()]
    sold_keys_count = len(sold_keys_ids)
    
    # Количество активированных ключей (статус ключа 'activated')
    activated_keys_count = UserKey.query.filter_by(
        user_id=user_id,
        status='activated'
    ).count()
    
    # Количество непроданных ключей на реализации
    unsold_consignment_keys_count = consignment_keys_count - sold_keys_count
    
    # Подготовка данных операций для отображения
    operations_data = []
    user_operations = UserOperation.query.filter_by(user_id=user_id).all()
    for op in user_operations:
        # Получаем объект ключа на основе product_id
        key = UserKey.query.get(op.product_id)
        key_value = key.key if key else 'N/A'
        
        operations_data.append({
            'id': op.id,
            'operation_type': op.operation_type,
            'amount': op.amount,
            'status': op.status,
            'date': op.date.strftime('%Y-%m-%d %H:%M:%S'),
            'key_value': key_value
        })
    
    return render_template('admin/user_summary.html',
                         user=user,
                         total_keys=total_keys,
                         status_counts=status_counts,
                         consignment_keys_count=consignment_keys_count,
                         sold_keys_count=sold_keys_count,
                         activated_keys_count=activated_keys_count,
                         unsold_consignment_keys_count=unsold_consignment_keys_count,
                         operations_data=operations_data)

@admin_bp.route('/reset_password_admin/<int:user_id>', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def reset_password_admin(user_id):
    """Сброс пароля пользователя администратором"""
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Генерируем новый пароль
        import secrets
        import string
        new_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        
        # Обновляем пароль пользователя
        user.password = new_password
        
        try:
            db.session.commit()
            flash(f'Пароль для пользователя {user.username} успешно сброшен. Новый пароль: {new_password}', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при сбросе пароля: {str(e)}', 'error')
        
        return redirect(url_for('admin.user_summary', user_id=user_id))
    
    return render_template('admin/reset_password_admin.html', user=user) 

@admin_bp.route('/assign_partner_manager', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def assign_partner_manager():
    """Назначение партнера менеджеру"""
    if request.method == 'POST':
        partner_id = request.form.get('partner_id')
        manager_id = request.form.get('manager_id')
        
        if not partner_id or not manager_id:
            flash('Необходимо выбрать партнера и менеджера', 'error')
            return redirect(url_for('admin.assign_partner_manager'))
        
        partner = User.query.filter_by(id=partner_id, role='partner').first()
        manager = User.query.filter_by(id=manager_id, role='manager').first()
        
        if not partner or not manager:
            flash('Пользователь не найден или имеет неправильную роль', 'error')
            return redirect(url_for('admin.assign_partner_manager'))
        
        # Обновляем связь партнер-менеджер
        partner.manager_id = manager_id
        
        try:
            db.session.commit()
            flash(f'Партнер {partner.username} успешно назначен менеджеру {manager.username}', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при назначении: {str(e)}', 'error')
        
        return redirect(url_for('admin.assign_partner_manager'))
    
    # Получаем партнеров и менеджеров
    partners = User.query.filter_by(role='partner').all()
    managers = User.query.filter_by(role='manager').all()
    
    return render_template('admin/assign_partner_manager.html', partners=partners, managers=managers) 

@admin_bp.route('/impersonate_partner/<int:user_id>')
@auth_required
@admin_only
def impersonate_partner(user_id):
    from flask_login import login_user
    from app.models.user import User
    from flask import session
    
    user = User.query.get_or_404(user_id)
    if user.role != 'partner':
        flash('Можно входить только под партнёрами', 'error')
        return redirect(url_for('admin.list_users'))
    
    # Сохраняем информацию об имперсонации в cookies
    response = redirect(url_for('admin.view_partner_dashboard', user_id=user.id))
    response.set_cookie('impersonating', 'true', max_age=3600)  # 1 час
    response.set_cookie('original_admin_id', str(g.user.id), max_age=3600)
    response.set_cookie('impersonated_user_id', str(user.id), max_age=3600)
    response.set_cookie('impersonated_username', user.username, max_age=3600)
    
    flash(f'Вы вошли в кабинет партнёра: {user.username}', 'success')
    return response

@admin_bp.route('/stop_impersonation')
@auth_required
def stop_impersonation():
    from flask_login import login_user, logout_user
    from app.models.user import User
    from flask import request
    
    if not request.cookies.get('impersonating'):
        flash('Вы не находитесь в режиме имперсонации', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Получаем оригинального админа
    original_admin_id = request.cookies.get('original_admin_id')
    original_admin = User.query.get(original_admin_id)
    if not original_admin:
        flash('Ошибка: оригинальный администратор не найден', 'error')
        return redirect(url_for('auth.login'))
    
    # Очищаем cookies имперсонации
    response = redirect(url_for('admin.dashboard'))
    response.delete_cookie('impersonating')
    response.delete_cookie('original_admin_id')
    response.delete_cookie('impersonated_user_id')
    response.delete_cookie('impersonated_username')
    
    flash('Вы вернулись в админ панель', 'success')
    return response

@admin_bp.route('/view_partner_dashboard/<int:user_id>')
@auth_required
@admin_only
def view_partner_dashboard(user_id):
    """Просмотр кабинета партнёра при имперсонации"""
    from app.services.partner_service import get_partner_data, calculate_days_left
    
    # Проверяем, что это партнёр
    user = User.query.get_or_404(user_id)
    if user.role != 'partner':
        flash('Можно просматривать только кабинеты партнёров', 'error')
        return redirect(url_for('admin.list_users'))
    
    # Получаем данные партнёра
    data = get_partner_data(user_id)
    
    return render_template('partner/dashboard.html', 
                         data=data,
                         calculate_days_left=calculate_days_left) 


@admin_bp.route('/helpdesk', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def helpdesk_list():
    """Список тикетов хелпдеска и смена статусов"""
    if request.method == 'POST':
        ticket_id = request.form.get('ticket_id')
        new_status = request.form.get('status')
        if ticket_id and new_status in ['open', 'in_progress', 'closed']:
            ticket = SupportTicket.query.get(int(ticket_id))
            if ticket:
                ticket.status = new_status
                db.session.commit()
                flash('Статус тикета обновлен', 'success')
        return redirect(url_for('admin.helpdesk_list'))

    tickets = SupportTicket.query.order_by(SupportTicket.created_at.desc()).all()

    # Подготовим данные из нашей базы для key fallback
    keys_map = {k.id: k for k in UserKey.query.all()}

    # Готовим расширенные данные по тикетам с подстановкой данных из /root/miner-data/file.db
    enriched = []
    import sqlite3
    try:
        conn = sqlite3.connect('/root/miner-data/file.db', timeout=30.0)
        cur = conn.cursor()
        for t in tickets:
            # Определяем строковое значение ключа
            key_value = getattr(t, 'key_value', None)
            if not key_value and t.user_key_id and t.user_key_id in keys_map:
                key_value = keys_map[t.user_key_id].key

            # Достаём профиль из внешней БД по ключу
            ext_user_id = None
            email = None
            phone = None
            telegram = None
            if key_value:
                try:
                    cur.execute(
                        """
                        SELECT u.id, u.email, u.phone_number, u.telegram_id
                        FROM users u
                        JOIN user_keys uk ON uk.user_id = u.id
                        WHERE uk.key = ?
                        LIMIT 1
                        """,
                        (key_value,),
                    )
                    row = cur.fetchone()
                    if row:
                        ext_user_id, email, phone, telegram = row
                except Exception as e:
                    pass

            # Формируем identifier: email -> phone -> telegram
            identifier = None
            for v in (email, phone, telegram):
                if v:
                    identifier = str(v)
                    break

            enriched.append({
                # Подсчёт непрочитанных сообщений от пользователя
                'unread_count': SupportMessage.query.filter_by(
                    ticket_id=t.id,
                    author_type="user",
                    read_by_admin=False
                ).count(),
                'id' : t.id,
                'created_at': t.created_at,
                'subject': t.subject,
                'message': t.message,
                'contact': t.contact,
                'status': t.status,
                'key_value': key_value,
                'ext_user_id': ext_user_id,
                'identifier': identifier,
            })
        conn.close()
    except Exception as e:
        # Если база недоступна — выводим без внешних данных
        for t in tickets:
            key_value = keys_map[t.user_key_id].key if t.user_key_id in keys_map else None
            enriched.append({
                'unread_count': 0,
                # Подсчёт непрочитанных сообщений от пользователя
                'unread_count': SupportMessage.query.filter_by(
                    ticket_id=t.id,
                    author_type="user",
                    read_by_admin=False
                ).count(),
                'id' : t.id,
                'created_at': t.created_at,
                'subject': t.subject,
                'message': t.message,
                'contact': t.contact,
                'status': t.status,
                'key_value': key_value,
                'ext_user_id': None,
                'identifier': None,
            })

    return render_template('admin/helpdesk.html', tickets_ext=enriched)
@admin_bp.route('/helpdesk/<int:ticket_id>')
@auth_required
@role_required('admin')

def helpdesk_chat(ticket_id):
    from app.models.support_ticket import SupportTicket
    from app.models.support_message import SupportMessage
    import sqlite3
    
    ticket = SupportTicket.query.get_or_404(ticket_id)
    messages = SupportMessage.query.filter_by(ticket_id=ticket_id).order_by(SupportMessage.id.asc()).all()
    
    # Получаем данные пользователя и ключа из внешней БД
    user_data = {}
    ext_user_id = None
    identifier = None
    
    if ticket.user_id:
        try:
            ext_conn = sqlite3.connect('/root/miner-data/file.db')
            ext_cur = ext_conn.cursor()
            
            # Получаем ключ
            ext_cur.execute('''
                SELECT uk.key 
                FROM user_keys uk 
                WHERE uk.user_id = ?
                LIMIT 1
            ''', (ticket.user_id,))
            row = ext_cur.fetchone()
            if row:
                user_data['key'] = row[0]
                
            # Получаем данные пользователя для identifier
            ext_cur.execute('''
                SELECT id, email, phone_number, telegram_id
                FROM users 
                WHERE id = ?
                LIMIT 1
            ''', (ticket.user_id,))
            row = ext_cur.fetchone()
            if row:
                ext_user_id = row[0]
                email = row[1]
                phone = row[2]
                telegram = row[3]
                
                # Формируем identifier: email -> phone -> telegram
                for v in (email, phone, telegram):
                    if v:
                        identifier = str(v)
                        break
                        
            ext_conn.close()
        except Exception as e:
            print(f'Failed to get user data: {e}')
    
    # Если ключа нет в user_data, используем key_value из тикета
    if not user_data.get('key') and ticket.key_value:
        user_data['key'] = ticket.key_value
    
    user_data['identifier'] = identifier
    user_data['ext_user_id'] = ext_user_id
    
    return render_template('admin/helpdesk_chat.html', 
                         ticket=ticket, 
                         messages=messages,
                         user_data=user_data)

