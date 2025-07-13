from app import db
from app.models import User, Tariff, Earning, PartnerManagerAssociation, ManagerSupervisorAssociation
from datetime import datetime

def calculate_daily_rate(duration):
    if duration <= 30:
        daily_rate = 700 / 30
    elif duration <= 90:
        daily_rate = 1950 / 90
    elif duration <= 180:
        daily_rate = 3600 / 180
    elif duration <= 365:
        daily_rate = 6000 / 365
    else:
        daily_rate = 6000 / 365
    return daily_rate

def handle_status_change(user_key, old_status):
    try:
        partner = User.query.filter_by(id=user_key.user_id).first()
        if not partner:
            return

        # Поиск менеджера (может отсутствовать)
        manager_association = PartnerManagerAssociation.query.filter_by(partner_id=partner.id).first()
        manager = None
        if manager_association:
            manager = User.query.filter_by(id=manager_association.manager_id).first()

        # Поиск супервизора (может отсутствовать)
        supervisor = None
        if manager:
            supervisor_association = ManagerSupervisorAssociation.query.filter_by(manager_id=manager.id).first()
            if supervisor_association:
                supervisor = User.query.filter_by(id=supervisor_association.supervisor_id).first()

        # Получение тарифа партнёра
        partner_tariff = Tariff.query.filter_by(id=partner.tariff_id).first()
        if not partner_tariff:
            return

        # Получение тарифа менеджера (если менеджер существует)
        manager_tariff = None
        if manager:
            manager_tariff = Tariff.query.filter_by(id=manager.tariff_id).first()

        # Получение тарифа супервизора (если супервизор существует)
        supervisor_tariff = None
        if supervisor:
            supervisor_tariff = Tariff.query.filter_by(id=supervisor.tariff_id).first()

        # Логика начисления при смене статуса
        if old_status == 'new' and user_key.status == 'active':
            # Начисление партнёру
            partner_initial_earning = partner_tariff.partner_initial_payment
            db.session.add(Earning(
                user_id=partner.id,
                key_id=user_key.id,
                amount=round(partner_initial_earning, 1),
                description=f"Первоначальный заработок партнёра за активацию ключа {user_key.key}"
            ))

            # Начисление менеджеру, если он есть
            if manager and manager_tariff:
                manager_initial_earning = manager_tariff.manager_initial_payment
                db.session.add(Earning(
                    user_id=manager.id,
                    key_id=user_key.id,
                    amount=round(manager_initial_earning, 1),
                    description=f"Первоначальный заработок менеджера за активацию ключа {user_key.key}"
                ))

            # Начисление супервизору, если он есть
            if supervisor and supervisor_tariff:
                supervisor_initial_earning = supervisor_tariff.supervisor_initial_payment
                db.session.add(Earning(
                    user_id=supervisor.id,
                    key_id=user_key.id,
                    amount=round(supervisor_initial_earning, 1),
                    description=f"Первоначальный заработок супервизора за активацию ключа {user_key.key}"
                ))

            db.session.commit()
    except Exception as e:
        pass

def calculate_earnings(user_key, previous_end_date):
    try:
        partner = User.query.filter_by(id=user_key.user_id).first()
        if not partner:
            return

        partner_tariff = Tariff.query.filter_by(id=partner.tariff_id).first()
        if not partner_tariff:
            return

        # Преобразование даты, если previous_end_date передан как строка
        if isinstance(previous_end_date, str):
            previous_end_date = datetime.strptime(previous_end_date, '%Y-%m-%d %H:%M:%S')

        # Даты для расчёта периода продления
        start_date = datetime.strptime(user_key.start_date, '%Y-%m-%d %H:%M:%S')
        end_date = datetime.strptime(user_key.end_date, '%Y-%m-%d %H:%M:%S')

        # Текущая дата используется для проверки актуальности
        current_date = datetime.now()
        effective_start_date = max(previous_end_date, current_date)

        # Точный расчёт количества дней продления
        extension_duration = round((end_date - effective_start_date).total_seconds() / (24 * 3600))

        if extension_duration <= 0:
            return

        # Расчет заработка с использованием точного количества дней продления
        daily_rate = calculate_daily_rate(extension_duration)
        
        # Начисление партнёру
        partner_earning = daily_rate * extension_duration * (partner_tariff.partner_subscription_percentage / 100)
        db.session.add(Earning(
            user_id=partner.id,
            key_id=user_key.id,
            amount=round(partner_earning, 1),
            description=f"Заработок партнёра за продление ключа {user_key.key} на {extension_duration} дней"
        ))

        # Поиск и начисление менеджеру
        manager_association = PartnerManagerAssociation.query.filter_by(partner_id=partner.id).first()
        if manager_association:
            manager = User.query.filter_by(id=manager_association.manager_id).first()
            if manager:
                manager_tariff = Tariff.query.filter_by(id=manager.tariff_id).first()
                if manager_tariff:
                    manager_earning = daily_rate * extension_duration * (manager_tariff.manager_subscription_percentage / 100)
                    db.session.add(Earning(
                        user_id=manager.id,
                        key_id=user_key.id,
                        amount=round(manager_earning, 1),
                        description=f"Заработок менеджера за продление ключа {user_key.key} на {extension_duration} дней"
                    ))

        # Поиск и начисление супервизору
        if manager:
            supervisor_association = ManagerSupervisorAssociation.query.filter_by(manager_id=manager.id).first()
            if supervisor_association:
                supervisor = User.query.filter_by(id=supervisor_association.supervisor_id).first()
                if supervisor:
                    supervisor_tariff = Tariff.query.filter_by(id=supervisor.tariff_id).first()
                    if supervisor_tariff:
                        supervisor_earning = daily_rate * extension_duration * (supervisor_tariff.supervisor_subscription_percentage / 100)
                        db.session.add(Earning(
                            user_id=supervisor.id,
                            key_id=user_key.id,
                            amount=round(supervisor_earning, 1),
                            description=f"Заработок супервизора за продление ключа {user_key.key} на {extension_duration} дней"
                        ))

        db.session.commit()
    except Exception as e:
        pass 