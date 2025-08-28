"""
WebSocket обработчик для мобильного helpdesk без авторизации
"""
from flask_socketio import join_room, leave_room, emit
from app import socketio, db
from app.models.support_ticket import SupportTicket
from app.models.support_message import SupportMessage

NAMESPACE = '/helpdesk_mobile'

@socketio.on('connect', namespace=NAMESPACE)
def on_connect_mobile():
    print("[WS Mobile] Client connected")
    """Подключение мобильного клиента без авторизации"""
    emit('connected', {'status': 'ok'})
    print(f'[WS Mobile] Client connected')

@socketio.on('disconnect', namespace=NAMESPACE)
def on_disconnect_mobile():
    """Отключение мобильного клиента"""
    print(f'[WS Mobile] Client disconnected')
@socketio.on('join', namespace=NAMESPACE)
def on_join_mobile(data):
    """Присоединение к комнате тикета"""
    ticket_id = data.get('ticket_id')
    if not ticket_id:
        return
    print(f"[WS Mobile] Client joined room ticket:{ticket_id}")
    
    try:
        ticket_id = int(ticket_id)
        ticket = SupportTicket.query.get(ticket_id)
        if not ticket:
            emit('error', {'message': 'Ticket not found'})
            return
        
        room = f'ticket:{ticket_id}'
        join_room(room)
        emit('joined', {'ticket_id': ticket_id})
        print(f'[WS Mobile] Client joined room {room}')
    except Exception as e:
        print(f'[WS Mobile] Error joining room: {e}')
        emit('error', {'message': str(e)})

@socketio.on('leave', namespace=NAMESPACE)
def on_leave_mobile(data):
    """Покидание комнаты тикета"""
    ticket_id = data.get('ticket_id')
    if not ticket_id:
        return
    
    try:
        ticket_id = int(ticket_id)
        room = f'ticket:{ticket_id}'
        leave_room(room)
        emit('left', {'ticket_id': ticket_id})
        print(f'[WS Mobile] Client left room {room}')
    except Exception as e:
        print(f'[WS Mobile] Error leaving room: {e}')

@socketio.on('message:send', namespace=NAMESPACE)
def on_message_send_mobile(data):
    """Отправка сообщения от мобильного клиента"""
    ticket_id = data.get('ticket_id')
    text = (data.get('text') or '').strip()
    
    if not ticket_id or not text:
        emit('error', {'message': 'Missing ticket_id or text'})
        return
    
    try:
        ticket_id = int(ticket_id)
        ticket = SupportTicket.query.get(ticket_id)
        if not ticket:
            emit('error', {'message': 'Ticket not found'})
            return
        
        # Создаем сообщение от пользователя
        msg = SupportMessage(
            ticket_id=ticket_id,
            author_id=ticket.user_id,  # Используем user_id из тикета
            author_type='user',
            text=text
        )
        db.session.add(msg)
        
        # Обновляем статус тикета если нужно
        if ticket.status == 'closed':
            ticket.status = 'open'
        
        db.session.commit()
        
        # Отправляем всем в комнате
        payload = {
            'id': msg.id,
            'author_type': msg.author_type,
            'text': msg.text,
            'created_at': msg.created_at.isoformat() if msg.created_at else None
        }
        
        room = f'ticket:{ticket_id}'
        emit('message:new', payload, room=room, include_self=True)
        
        # Также отправляем в основной namespace для админов
        socketio.emit("message:new", msg.to_dict(), room=room, namespace="/helpdesk")
        
        # Обновляем список тикетов в админке
        from app.ws_helpdesk import broadcast_ticket_update
        broadcast_ticket_update(ticket_id)
        
        print(f'[WS Mobile] Message sent to room {room}: {text[:50]}')
        
    except Exception as e:
        print(f'[WS Mobile] Error sending message: {e}')
        db.session.rollback()
        emit('error', {'message': str(e)})

@socketio.on('typing', namespace=NAMESPACE)
def on_typing_mobile(data):
    """Индикатор набора текста"""
    ticket_id = data.get('ticket_id')
    if not ticket_id:
        return
    
    try:
        ticket_id = int(ticket_id)
        room = f'ticket:{ticket_id}'
        emit('typing', {'ticket_id': ticket_id}, room=room, include_self=False)
    except Exception as e:
        print(f'[WS Mobile] Error in typing: {e}')
# Register the namespace with socketio  
