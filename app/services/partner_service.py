from app import db
from app.models import User, UserKey, Tariff, Earning, PartnerManagerAssociation, ManagerSupervisorAssociation
from datetime import datetime

def get_partner_data(partner_id):
    """Получение всех данных партнера"""
    
    # Менеджер и супервизор
    manager = supervisor = None
    mgr_assoc = PartnerManagerAssociation.query.filter_by(partner_id=partner_id).first()
    if mgr_assoc:
        manager = User.query.get(mgr_assoc.manager_id)
        sup_assoc = ManagerSupervisorAssociation.query.filter_by(manager_id=manager.id).first() if manager else None
        supervisor = User.query.get(sup_assoc.supervisor_id) if sup_assoc else None

    # Ключи партнёра
    partner_keys = (db.session.query(UserKey, User)
                    .join(User, UserKey.user_id == User.id)
                    .filter(User.id == partner_id)
                    .all())

    total_new_devices = sum(1 for key, _ in partner_keys if key.status == 'new')
    total_active_devices = sum(1 for key, _ in partner_keys if key.status == 'active')

    # Тарифы
    main_tariff = Tariff.query.get(User.query.get(partner_id).tariff_id) if User.query.get(partner_id).tariff_id else None
    tariff_ids = {key.tariff_id for key, _ in partner_keys if key.tariff_id}
    key_tariffs = Tariff.query.filter(Tariff.id.in_(tariff_ids)).all() if tariff_ids else []
    assigned_tariffs = ([main_tariff] if main_tariff else []) + key_tariffs

    # Финансы
    initial_earnings = (Earning.query
                        .filter(Earning.user_id == partner_id,
                                Earning.description.like('Первоначальный заработок партнёра%'))
                        .all())
    earnings = sum(e.amount for e in initial_earnings)

    earnings_data = Earning.query.filter_by(user_id=partner_id).all()
    earnings_summary = sum(e.amount for e in earnings_data)

    return {
        'manager': manager,
        'supervisor': supervisor,
        'partner_keys': partner_keys,
        'total_new_devices': total_new_devices,
        'total_active_devices': total_active_devices,
        'assigned_tariffs': assigned_tariffs,
        'earnings': earnings,
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