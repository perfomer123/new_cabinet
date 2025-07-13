from app import db
from app.models import User, UserKey, Tariff, Earning, PartnerManagerAssociation, ManagerSupervisorAssociation
from datetime import datetime

def get_manager_data(manager_id):
    """Получение всех данных менеджера"""
    
    # Супервизор
    supervisor = None
    sup_assoc = ManagerSupervisorAssociation.query.filter_by(manager_id=manager_id).first()
    if sup_assoc:
        supervisor = User.query.get(sup_assoc.supervisor_id)

    # Партнеры менеджера
    partner_associations = PartnerManagerAssociation.query.filter_by(manager_id=manager_id).all()
    partners = [User.query.get(assoc.partner_id) for assoc in partner_associations if User.query.get(assoc.partner_id)]

    # Ключи всех партнеров менеджера
    partner_ids = [p.id for p in partners]
    partner_keys = []
    total_new_devices = 0
    total_active_devices = 0
    
    if partner_ids:
        keys_query = (db.session.query(UserKey, User)
                      .join(User, UserKey.user_id == User.id)
                      .filter(User.id.in_(partner_ids)))
        partner_keys = keys_query.all()
        
        total_new_devices = sum(1 for key, _ in partner_keys if key.status == 'new')
        total_active_devices = sum(1 for key, _ in partner_keys if key.status == 'active')

    # Финансы менеджера
    earnings_data = Earning.query.filter_by(user_id=manager_id).all()
    earnings_summary = sum(e.amount for e in earnings_data)

    return {
        'supervisor': supervisor,
        'partners': partners,
        'partner_keys': partner_keys,
        'total_new_devices': total_new_devices,
        'total_active_devices': total_active_devices,
        'earnings_data': earnings_data,
        'earnings_summary': earnings_summary
    }

def calculate_days_left(end_date):
    """Расчет оставшихся дней"""
    if not end_date:
        return ''
    if isinstance(end_date, datetime):
        return (end_date - datetime.now()).days
    try:
        dt = datetime.strptime(str(end_date), '%Y-%m-%d %H:%M:%S')
        return (dt - datetime.now()).days
    except Exception:
        return '' 