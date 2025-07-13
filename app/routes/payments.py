from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_required, current_user
from app.models.payment import Payment
from app.models.user_key import UserKey
from app.models.tariff import Tariff
from app.services.payment_service import PaymentService
from app.utils.decorators import auth_required, role_required
from app import db
import yookassa
from yookassa import Payment as YooKassaPayment
from yookassa.domain.exceptions import UnauthorizedError
from datetime import datetime, timedelta
import logging

payments_bp = Blueprint('payments', __name__)

@payments_bp.route('/pay', methods=['GET', 'POST'])
def pay():
    key = request.args.get('key', '')  # Получаем ключ из GET-параметра, если он есть

    if request.method == 'POST':
        key = request.form['key']
        duration = int(request.form['duration'])
        
        # Проверяем ключ в базе данных
        user_key = UserKey.query.filter_by(key=key).first()
        
        if not user_key:
            flash('Такого ключа не существует', 'error')
            return redirect(url_for('payments.pay'))
        
        if user_key.status not in ['new', 'active', 'inactive']:
            flash('Неверный статус ключа', 'error')
            return redirect(url_for('payments.pay'))

        extension_days = get_extension_days(duration)
        amount = get_amount(duration)
        
        # Создание платежа в YooKassa
        try:
            payment = YooKassaPayment.create({
                "amount": {
                    "value": amount,
                    "currency": "RUB"
                },
                "confirmation": {
                    "type": "redirect",
                    "return_url": url_for('payments.payment_success', key=key, duration=duration, _external=True)
                },
                "capture": True,
                "description": f"Продление ключа {key} на {extension_days} дней"
            })
        except UnauthorizedError as e:
            logging.error(f"Ошибка авторизации: {e}")
            flash('Ошибка авторизации при создании платежа. Пожалуйста, проверьте учетные данные.', 'error')
            return redirect(url_for('payments.pay'))
        
        # Добавляем payment_id в таблицу payment
        new_payment = Payment(
            user_id=user_key.user_id,
            tariff_id=user_key.tariff_id,
            amount=amount,
            extension_days=extension_days,
            key=key,
            payment_id=payment.id
        )
        db.session.add(new_payment)
        db.session.commit()
        
        # Добавляем payment_id в сессию
        session['payment_id'] = payment.id
        logging.info(f"Создан платеж: {payment.id}, сумма: {amount}, для ключа: {key}")
        return redirect(payment.confirmation.confirmation_url)

    return render_template('payments/pay.html', key=key)

@payments_bp.route('/payment_success', methods=['GET', 'POST'])
def payment_success():
    key = request.args.get('key')
    duration = request.args.get('duration')
    
    if key and duration:
        # Здесь можно добавить дополнительную логику обработки успешного платежа
        flash('Платеж успешно обработан!', 'success')
    
    return render_template('payments/success.html')

@payments_bp.route('/yookassa_notification', methods=['POST'])
def yookassa_notification():
    # Обработка уведомлений от YooKassa
    payment_id = request.json.get('object', {}).get('id')
    if payment_id:
        process_successful_payment(payment_id)
    return '', 200

def process_successful_payment(payment_id):
    """Обработка успешного платежа"""
    payment = Payment.query.filter_by(payment_id=payment_id, processed=False).first()
    if not payment:
        return
    
    # Обновляем статус платежа
    payment.processed = True
    db.session.commit()
    
    # Продлеваем ключ
    user_key = UserKey.query.filter_by(key=payment.key).first()
    if user_key:
        # Логика продления ключа
        current_end_date = datetime.strptime(user_key.end_date, '%Y-%m-%d') if user_key.end_date else datetime.now()
        new_end_date = current_end_date + timedelta(days=payment.extension_days)
        user_key.end_date = new_end_date.strftime('%Y-%m-%d')
        user_key.status = 'active'
        db.session.commit()

def get_extension_days(duration):
    """Получение количества дней продления"""
    duration_mapping = {
        1: 30,
        2: 90,
        3: 180,
        4: 365
    }
    return duration_mapping.get(duration, 30)

def get_amount(duration):
    """Получение суммы платежа"""
    amount_mapping = {
        1: 299.0,
        2: 799.0,
        3: 1499.0,
        4: 2999.0
    }
    return amount_mapping.get(duration, 299.0)

def calculate_new_end_date(current_end_date, extension_days):
    """Расчет новой даты окончания"""
    if isinstance(current_end_date, str):
        current_end_date = datetime.strptime(current_end_date, '%Y-%m-%d')
    return current_end_date + timedelta(days=extension_days) 