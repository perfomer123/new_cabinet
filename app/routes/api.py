import time
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, session
from app.utils.decorators import auth_required, role_required
from app.services.device_service import DeviceService
from app.services.payment_service import PaymentService
from app.models.user import User
from app.models.user_key import UserKey
from app.utils.helpers import calculate_days_left, format_date
from app import db

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/health')
def health():
    return jsonify({'status': 'ok'})

@api_bp.route('/device-purchase', methods=['POST'])
def device_purchase():
    """API для покупки устройства"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
        
        device_id = data.get('device_id')
        amount = data.get('amount')
        phone_number = data.get('phone_number')
        email = data.get('email')
        delivery_address = data.get('delivery_address')
        product_name = data.get('product_name')
        platform_id = data.get('platform_id')
        
        if not all([device_id, amount, phone_number]):
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        # Здесь должна быть логика создания заказа
        # Пока возвращаем успешный ответ
        
        return jsonify({
            'status': 'success',
            'message': 'Device purchase request received',
            'order_id': f'ORDER_{device_id}_{int(time.time())}'
        }), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/check-device', methods=['POST'])
def check_device():
    """API для проверки устройства"""
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        
        if not device_id:
            return jsonify({'status': 'error', 'message': 'Device ID required'}), 400
        
        # Получаем данные устройства
        device_data = DeviceService.get_device_data_by_uid(device_id)
        
        if device_data:
            return jsonify({
                'status': 'success',
                'device': device_data
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Device not found'
            }), 404
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/payment', methods=['POST'])
def process_payment():
    """API для обработки платежей"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'status': 'error', 'message': 'Invalid JSON data'}), 400
        
        amount = data.get('amount')
        key = data.get('key')
        duration = data.get('duration')
        
        if not all([amount, key, duration]):
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        # Создаем платеж в YooKassa
        payment = PaymentService.create_yookassa_payment(
            amount=amount,
            description=f"Продление подписки для ключа {key}",
            return_url="https://cabinet.sovamonitoring.com/payment_success"
        )
        
        if payment:
            return jsonify({
                'status': 'success',
                'payment_id': payment.id,
                'confirmation_url': payment.confirmation.confirmation_url
            }), 200
        else:
            return jsonify({'status': 'error', 'message': 'Failed to create payment'}), 500
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/partner_data', methods=['GET'])
@auth_required
@role_required('partner')
def get_partner_data():
    """API для получения данных партнера"""
    try:
        user_id = request.current_user.id
        
        # Получаем ключи пользователя
        keys = UserKey.query.filter_by(user_id=user_id).all()
        
        # Получаем статистику
        active_keys = UserKey.query.filter_by(user_id=user_id, status='active').count()
        expired_keys = UserKey.query.filter_by(user_id=user_id, status='expired').count()
        
        # Получаем заработки
        from app.models.payment import Earning
        earnings = Earning.query.filter_by(user_id=user_id).all()
        total_earnings = sum(earning.amount for earning in earnings)
        
        return jsonify({
            'status': 'success',
            'data': {
                'user_id': user_id,
                'keys': [{
                    'id': key.id,
                    'key': key.key,
                    'status': key.status,
                    'start_date': key.start_date,
                    'end_date': key.end_date
                } for key in keys],
                'stats': {
                    'active_keys': active_keys,
                    'expired_keys': expired_keys,
                    'total_earnings': total_earnings
                }
            }
        }), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/dashboard/stats')
@auth_required
def dashboard_stats():
    """API для статистики дашборда"""
    try:
        user_id = request.current_user.id
        user_role = request.current_user.role
        
        if user_role == 'admin':
            # Для админа показываем общую статистику
            active_devices = UserKey.query.filter_by(status='active').count()
            expiring_devices = UserKey.query.filter(
                UserKey.status == 'active',
                UserKey.end_date < (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
            ).count()
        else:
            # Для обычных пользователей показываем их статистику
            active_devices = UserKey.query.filter_by(user_id=user_id, status='active').count()
            expiring_devices = UserKey.query.filter(
                UserKey.user_id == user_id,
                UserKey.status == 'active',
                UserKey.end_date < (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
            ).count()
        
        return jsonify({
            'active_devices': active_devices,
            'expiring_devices': expiring_devices,
            'total_earnings': 0,  # TODO: Реализовать подсчет заработков
            'days_left': 0  # TODO: Реализовать подсчет дней
        }), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/dashboard/devices')
@auth_required
def dashboard_devices():
    """API для устройств дашборда"""
    try:
        user_id = request.current_user.id
        user_role = request.current_user.role
        
        if user_role == 'admin':
            # Для админа показываем все устройства
            keys = UserKey.query.all()
        else:
            # Для обычных пользователей показываем их устройства
            keys = UserKey.query.filter_by(user_id=user_id).all()
        
        devices = []
        for key in keys:
            days_left = calculate_days_left(key.end_date) if key.end_date else 0
            
            devices.append({
                'id': key.id,
                'key': key.key,
                'status': key.status,
                'start_date': format_date(key.start_date),
                'end_date': format_date(key.end_date),
                'days_left': days_left
            })
        
        return jsonify({
            'status': 'success',
            'devices': devices
        }), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/dashboard/notifications')
@auth_required
def dashboard_notifications():
    """API для уведомлений дашборда"""
    try:
        user_id = request.current_user.id
        
        # Получаем уведомления пользователя
        notifications = []  # TODO: Реализовать получение уведомлений
        
        return jsonify({
            'status': 'success',
            'notifications': notifications
        }), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500 