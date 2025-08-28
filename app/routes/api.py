import time
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, session, current_app
from app.utils.decorators import auth_required, role_required
from app.services.device_service import DeviceService
from app.services.payment_service import PaymentService
from app.models.user import User
from app.models.user_key import UserKey
from app.models.support_ticket import SupportTicket
from app.models.support_message import SupportMessage
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


from app.models.support_ticket import SupportTicket

@api_bp.route('/helpdesk/tickets', methods=['POST'])
def create_support_ticket():
    """Создать тикет в хелпдеске.
    Ожидаемые поля JSON: subject, message, key_id (int) или key (str), contact (optional)
    """
    try:
        data = request.get_json(silent=True) or {}
        with open("/tmp/helpdesk_debug.log", "a") as f: f.write(f"Received: {data}\n")
        try:
            current_app.logger.info('[helpdesk] create_ticket payload: %s', data)
        except Exception:
            pass
        subject = data.get('subject')
        message = data.get('message')
        key_id = data.get('key_id')
        key_value = data.get('key')
        contact = data.get('contact')

        if not subject or not message:
            return jsonify({'status': 'error', 'message': 'subject and message are required'}), 400

        user_id = None
        user_key_id = None

                # # Явно принимаем user_id из запроса (внешний id из /root/miner-data/file.db)
        #         user_id_req = (data.get('user_id') if isinstance(data, dict) else None)
        #         if isinstance(user_id_req, (int,)):
        #             user_id = user_id_req
        #         elif isinstance(user_id_req, str) and user_id_req.isdigit():
        #             user_id = int(user_id_req)
        # 
        # 
        # Try to resolve user by cookie if present
        #         try:
        #             token = request.cookies.get('token')
        #             if token:
        #                 from app.services.auth_service import verify_jwt_token
        #                 payload = verify_jwt_token(token)
        #                 if payload and payload.get('user_id'):
        #                     user_id = payload.get('user_id')
        #         except Exception:
        #             pass
        # 
        #         # Resolve by key: prefer text key; fallback to id; derive user_id from key
        uk = None
        # Сначала ищем пользователя во внешней БД
        if key_value:
            try:
                import sqlite3
                ext_conn = sqlite3.connect('/root/miner-data/file.db')
                ext_cur = ext_conn.cursor()
                ext_cur.execute('''
                    SELECT u.id FROM users u
                    JOIN user_keys uk ON uk.user_id = u.id
                    WHERE uk.key = ?
                    LIMIT 1
                ''', (key_value,))
                row = ext_cur.fetchone()
                if row:
                    user_id = row[0]
                    current_app.logger.info('[helpdesk] Found user_id=%s for key=%s in external DB', user_id, key_value)
                ext_conn.close()
            except Exception as e:
                current_app.logger.warning('[helpdesk] Failed to find user in external DB: %s', e)
            
            # Также ищем в локальной БД для user_key_id
            uk = UserKey.query.filter_by(key=key_value).first()
        if uk:
            user_key_id = uk.id
            # Используем user_id из локальной БД только если не нашли во внешней
            if not user_id:
                user_id = uk.user_id


        try:
            current_app.logger.info('[helpdesk] resolved user_key_id=%s user_id=%s key_value=%s', user_key_id, user_id, key_value)
        except Exception:
            pass

        # Если есть ключ, ищем user_id во внешней БД
        if key_value and not user_id:
            try:
                import sqlite3
                conn = sqlite3.connect('/root/miner-data/file.db')
                cur = conn.cursor()
                cur.execute("""
                    SELECT u.id FROM users u
                    JOIN user_keys uk ON uk.user_id = u.id
                    WHERE uk.key = ?
                    LIMIT 1
                """, (key_value,))
                row = cur.fetchone()
                if row:
                    user_id = row[0]
                    current_app.logger.info(f'[helpdesk] Found user_id={user_id} for key={key_value}')
                conn.close()
            except Exception as e:
                current_app.logger.warning(f'[helpdesk] Failed to get user_id for key {key_value}: {e}')
        
        current_app.logger.error(f"[helpdesk] Creating ticket with: user_id={user_id}, user_key_id={user_key_id}, key_value={key_value}")
        ticket = SupportTicket(
            user_id=user_id,
            user_key_id=user_key_id,
            subject=subject,
            message=message,
            key_value=key_value,
            status='open',
            contact=contact,
            source='app'
        )
        db.session.add(ticket)
        db.session.commit()

        return jsonify({'status': 'success', 'ticket_id': ticket.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500



@api_bp.route('/helpdesk/tickets/<int:ticket_id>/messages', methods=['GET'])
@auth_required
def get_ticket_messages(ticket_id):
    try:
        user_id = request.current_user.id if hasattr(request, 'current_user') else None
        t = SupportTicket.query.get_or_404(ticket_id)
        if not (request.current_user.role == 'admin' or (t.user_id and t.user_id == user_id)):
            return jsonify({'status': 'error', 'message': 'Forbidden'}), 403
        after_id = request.args.get('after_id', type=int)
        q = SupportMessage.query.filter_by(ticket_id=ticket_id)
        if after_id:
            q = q.filter(SupportMessage.id > after_id)
        msgs = q.order_by(SupportMessage.id.asc()).all()
        # Добавляем первое сообщение с телом тикета
        first_msg = {
            "id": 0,
            "author_type": "user",
            "text": t.message,
            "created_at": t.created_at.isoformat() if t.created_at else None
        }
        messages_list = [first_msg] + [m.to_dict() for m in msgs]
        return jsonify({"status": "success", "messages": messages_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/helpdesk/tickets/<int:ticket_id>/messages', methods=['POST'])
@auth_required
def post_ticket_message(ticket_id):
    try:
        data = request.get_json(silent=True) or {}
        text = (data.get('text') or '').strip()
        if not text:
            return jsonify({'status': 'error', 'message': 'text required'}), 400
        user = request.current_user
        t = SupportTicket.query.get_or_404(ticket_id)
        if not (user.role == 'admin' or (t.user_id and t.user_id == user.id)):
            return jsonify({'status': 'error', 'message': 'Forbidden'}), 403
        author_type = 'admin' if user.role == 'admin' else 'user'
        m = SupportMessage(ticket_id=ticket_id, author_id=user.id, author_type=author_type, text=text)
        db.session.add(m)
        db.session.commit()
        # Отправляем через WebSocket в оба namespace
        from app import socketio
        msg_dict = m.to_dict()
        socketio.emit("message:new", msg_dict, room=f"ticket:{ticket_id}", namespace="/helpdesk_mobile")
        socketio.emit("message:new", msg_dict, room=f"ticket:{ticket_id}", namespace="/helpdesk")
        db.session.commit()
        return jsonify({'status': 'success', 'message': m.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


# Mobile API endpoints for helpdesk chat

@api_bp.route('/helpdesk/mobile/tickets/<int:ticket_id>/messages', methods=['GET'])
def get_ticket_messages_mobile(ticket_id):
    """Получить сообщения тикета (для мобильного приложения)"""
    try:
        t = SupportTicket.query.get_or_404(ticket_id)
        
        # Получаем все сообщения тикета
        msgs = SupportMessage.query.filter_by(ticket_id=ticket_id).order_by(SupportMessage.id.asc()).all()
        
        # Добавляем первое сообщение с текстом тикета
        messages = [{
            'id': 0,
            'author_type': 'user', 
            'text': t.message,
            'created_at': t.created_at.isoformat() if t.created_at else None,
            'read_by_admin': False
        }]
        
        # Добавляем остальные сообщения
        messages.extend([{
            'id': m.id,
            'author_type': m.author_type,
            'text': m.text,
            'created_at': m.created_at.isoformat() if m.created_at else None,
            'read_by_admin': m.read_by_admin,
            'read_by_user': m.read_by_user
        } for m in msgs])
        
        return jsonify({'status': 'success', 'messages': messages})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/helpdesk/mobile/tickets/<int:ticket_id>/messages', methods=['POST'])
def post_ticket_message_mobile(ticket_id):
    """Отправить сообщение в тикет (для мобильного приложения)"""
    try:
        data = request.get_json(silent=True) or {}
        text = (data.get('text') or '').strip()
        if not text:
            return jsonify({'status': 'error', 'message': 'text required'}), 400
        
        t = SupportTicket.query.get_or_404(ticket_id)
        
        # Создаем сообщение от пользователя
        m = SupportMessage(
            ticket_id=ticket_id, 
            author_id=t.user_id,  # Используем user_id из тикета
            author_type='user', 
            text=text
        )
        db.session.add(m)
        # Отправляем через WebSocket в оба namespace
        from app import socketio
        msg_dict = m.to_dict()
        socketio.emit("message:new", msg_dict, room=f"ticket:{ticket_id}", namespace="/helpdesk_mobile")
        socketio.emit("message:new", msg_dict, room=f"ticket:{ticket_id}", namespace="/helpdesk")
        
        # Обновляем статус тикета если нужно
        if t.status == 'closed':
            t.status = 'open'
        
        db.session.commit()
        
        return jsonify({
            'status': 'success', 
            'message': {
                'id': m.id,
                'author_type': m.author_type,
                'text': m.text,
                'created_at': m.created_at.isoformat() if m.created_at else None
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/helpdesk/mobile/tickets', methods=['GET'])
def get_user_tickets_mobile():
    """Получить список тикетов пользователя (для мобильного приложения)"""
    try:
        import sqlite3
        # Получаем параметры из запроса
        user_id = request.args.get('user_id', type=int)
        key = request.args.get('key', type=str)
        
        # Если передан ключ, находим user_id по ключу
        if key and not user_id:
            # Проверяем во внешней БД
            ext_conn = sqlite3.connect('/root/miner-data/file.db')
            ext_cur = ext_conn.cursor()
            ext_cur.execute('SELECT id FROM users WHERE key = ?', (key,))
            row = ext_cur.fetchone()
            ext_conn.close()
            if row:
                user_id = row[0]
        
        # Получаем тикеты
        query = SupportTicket.query.order_by(SupportTicket.created_at.desc())
        
        if user_id:
            query = query.filter_by(user_id=user_id)
        elif key:
            query = query.filter_by(key_value=key)
        else:
            # Если нет фильтров, возвращаем пустой список
            return jsonify({'status': 'success', 'tickets': []})
        
        tickets = query.all()
        
        tickets_data = []
        for t in tickets:
            # Получаем последнее сообщение
            last_msg = SupportMessage.query.filter_by(ticket_id=t.id).order_by(
                SupportMessage.created_at.desc()
            ).first()
            
            tickets_data.append({
                'id': t.id,
                'subject': t.subject,
                'status': t.status,
                'created_at': t.created_at.isoformat() if t.created_at else None,
                'last_message': last_msg.text if last_msg else t.message,
                'last_message_at': last_msg.created_at.isoformat() if last_msg and last_msg.created_at else None,
                'unread_count': SupportMessage.query.filter_by(
                    ticket_id=t.id, read_by_user=False, author_type='admin'
                ).count()
            })
        
        return jsonify({'status': 'success', 'tickets': tickets_data})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/helpdesk/mobile/tickets/<int:ticket_id>/read', methods=['POST'])
def mark_ticket_messages_read_mobile(ticket_id):
    """Отметить все сообщения от админа как прочитанные (для мобильного)"""
    try:
        # Отмечаем все сообщения от админа в этом тикете как прочитанные пользователем
        SupportMessage.query.filter_by(
            ticket_id=ticket_id, 
            author_type='admin'
        ).update({'read_by_user': True})
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api_bp.route('/helpdesk/tickets/<int:ticket_id>/read', methods=['POST'])
@auth_required
def mark_ticket_messages_read_admin(ticket_id):
    """Отметить все сообщения от пользователя как прочитанные (для админа)"""
    try:
        # Проверяем права
        user = request.current_user
        if user.role != 'admin':
            return jsonify({'status': 'error', 'message': 'Forbidden'}), 403
        
        # Отмечаем все сообщения от пользователя как прочитанные админом
        SupportMessage.query.filter_by(
            ticket_id=ticket_id, 
            author_type='user'
        ).update({'read_by_admin': True})
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
