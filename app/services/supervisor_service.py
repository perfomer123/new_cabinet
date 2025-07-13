from app import db
from app.models import User, UserKey, Tariff, Earning, PartnerManagerAssociation, ManagerSupervisorAssociation
from datetime import datetime

def get_supervisor_data(supervisor_id):
    # Менеджеры супервизора
    manager_associations = ManagerSupervisorAssociation.query.filter_by(supervisor_id=supervisor_id).all()
    managers = [User.query.get(assoc.manager_id) for assoc in manager_associations if User.query.get(assoc.manager_id)]

    # Партнеры всех менеджеров
    partner_ids = []
    for manager in managers:
        partner_assocs = PartnerManagerAssociation.query.filter_by(manager_id=manager.id).all()
        partner_ids.extend([assoc.partner_id for assoc in partner_assocs])
    partners = [User.query.get(pid) for pid in partner_ids if User.query.get(pid)]

    # Ключи всех партнеров
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

    # Финансы супервизора
    earnings_data = Earning.query.filter_by(user_id=supervisor_id).all()
    earnings_summary = sum(e.amount for e in earnings_data)

    return {
        'managers': managers,
        'partners': partners,
        'partner_keys': partner_keys,
        'total_new_devices': total_new_devices,
        'total_active_devices': total_active_devices,
        'earnings_data': earnings_data,
        'earnings_summary': earnings_summary
    }

def calculate_days_left(end_date):
    if not end_date:
        return ''
    if isinstance(end_date, datetime):
        return (end_date - datetime.now()).days
    try:
        dt = datetime.strptime(str(end_date), '%Y-%m-%d %H:%M:%S')
        return (dt - datetime.now()).days
    except Exception:
        return '' 