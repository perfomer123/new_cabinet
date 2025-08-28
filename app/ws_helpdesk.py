from flask import request, g
from flask_socketio import join_room, leave_room, emit
from app import socketio, db
from app.models.support_ticket import SupportTicket
from app.models.support_message import SupportMessage
from app.models.user import User
from app.utils.decorators import verify_jwt_token

NAMESPACE = '/helpdesk'

# Helper: authorize connection by token

def _auth_from_token():
    token = request.args.get('token') or request.cookies.get('token')
    if not token:
        return None
    payload = verify_jwt_token(token)
    if not payload:
        return None
    return payload

@socketio.on('connect', namespace=NAMESPACE)
def on_connect():
    print("[WS Admin] Client connected")
    payload = _auth_from_token()
    print(f"[WS Admin] Auth payload: {payload}")
    if not payload:
        return False  # reject
    # Optionally set g.user_id
    g.user_id = payload.get('user_id')
    emit('connected', {'status': 'ok'})

@socketio.on('join', namespace=NAMESPACE)
def on_join(data):
    payload = _auth_from_token()
    print(f"[WS Admin] Auth payload: {payload}")
    if not payload:
        return False
    user_id = payload.get('user_id')
    role = User.query.get(user_id).role if user_id else None
    ticket_id = int(data.get('ticket_id'))
    ticket = SupportTicket.query.get(ticket_id)
    if not ticket:
        return
    # Access check: owner or admin
    
    # Если это администратор, отмечаем все сообщения от пользователя как прочитанные
    if role == 'admin':
        SupportMessage.query.filter_by(
            ticket_id=ticket_id,
            author_type='user',
            read_by_admin=False
        ).update({'read_by_admin': True})
        db.session.commit()
    if not (role == 'admin' or (ticket.user_id and ticket.user_id == user_id)):
        return
    room = f'ticket:{ticket_id}'
    join_room(room)
    emit('joined', {'ticket_id': ticket_id})

@socketio.on('leave', namespace=NAMESPACE)
def on_leave(data):
    ticket_id = int(data.get('ticket_id'))
    room = f'ticket:{ticket_id}'
    leave_room(room)
    emit('left', {'ticket_id': ticket_id})

@socketio.on('message:send', namespace=NAMESPACE)
def on_message_send(data):
    print(f"[WS Admin] message:send received: {data}")
    payload = _auth_from_token()
    print(f"[WS Admin] Auth payload: {payload}")
    if not payload:
        return False
    user_id = payload.get('user_id')
    user = User.query.get(user_id) if user_id else None
    ticket_id = int(data.get('ticket_id'))
    text = (data.get('text') or '').strip()
    if not text:
        return
    ticket = SupportTicket.query.get(ticket_id)
    if not ticket:
        return
    # Access check
    if not (user and (user.role == 'admin' or ticket.user_id == user.id)):
        return
    author_type = 'admin' if user.role == 'admin' else 'user'
    msg = SupportMessage(ticket_id=ticket_id, author_id=user.id, author_type=author_type, text=text)
    db.session.add(msg)
    db.session.commit()
    payload = msg.to_dict()
    emit('message:new', payload, room=f'ticket:{ticket_id}')
    print(f"[WS Admin] Emitting message to room ticket:{ticket_id}")
    # Также отправляем в мобильный namespace
    socketio.emit('message:new', payload, room=f'ticket:{ticket_id}', namespace='/helpdesk_mobile')
    print(f"[WS Admin] Emitting message to room ticket:{ticket_id}")

# Register the namespace with socketio

@socketio.on('tickets:list', namespace=NAMESPACE)
def on_tickets_list(data):
    print(f"[WS Admin] tickets:list received from client")
    """Подписка на обновления списка тикетов"""
    payload = _auth_from_token()
    if not payload:
        return False
    
    join_room('tickets_updates')
    emit('tickets:subscribed', {'status': 'ok'})
    print('[WS Admin] Client subscribed to ticket updates')

def broadcast_ticket_update(ticket_id, update_type='new_message'):
    """Отправка обновления о тикете всем подписчикам"""
    print(f"[DEBUG] broadcast_ticket_update called for ticket {ticket_id}")
    ticket = SupportTicket.query.get(ticket_id)
    if ticket:
        # Получаем последнее сообщение
        last_msg = SupportMessage.query.filter_by(ticket_id=ticket_id).order_by(SupportMessage.id.desc()).first()
        
        # Считаем непрочитанные сообщения от пользователя
        unread_count = SupportMessage.query.filter_by(
            ticket_id=ticket_id,
            author_type='user',
            read_by_admin=False
        ).count()
        
        update_data = {
            'ticket_id': ticket_id,
            'type': update_type,
            'ticket': {
                'id': ticket.id,
                'subject': ticket.subject,
                'status': ticket.status,
                'created_at': ticket.created_at.isoformat() if ticket.created_at else None,
                'last_message': last_msg.text if last_msg else None,
                'last_message_at': last_msg.created_at.isoformat() if last_msg and last_msg.created_at else None
            },
            'unread_count': unread_count
        }
        socketio.emit('tickets:update', update_data, 
                     room='tickets_updates', 
                     namespace=NAMESPACE)
        print(f'[WS Admin] Broadcast ticket update for ticket {ticket_id}, unread: {unread_count}')
        print(f'[WS Admin] Broadcast ticket update for ticket {ticket_id}')
