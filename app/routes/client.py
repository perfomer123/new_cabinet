from flask import Blueprint, render_template, request, flash, redirect, url_for, g
from app.utils.decorators import auth_required, role_required
from app.utils.helpers import get_data_for_user, extend_key_subscription
from app.models.payment import Payment
from app.models.association import PartnerManagerAssociation, ManagerSupervisorAssociation
from app import db
from datetime import datetime
import pandas as pd
import sqlite3
from sqlalchemy import create_engine
import os
import logging
logging.basicConfig(level=logging.INFO)

client_bp = Blueprint('client', __name__)

@client_bp.route('/client/<identifier>', methods=['GET', 'POST'])
@auth_required
@role_required('admin')
def client_details(identifier):
    """
    Эндпоинт выводит карточку клиента (ключи, платежи, партнёры)
    и позволяет вручную продлить ключ (POST) через модальное окно.
    Сохраняем user_id как int, чтобы в БД не попадали байты.
    """

    # =========================================
    # 1) Обработка POST (ручное продление)
    # =========================================
    if request.method == 'POST':
        extend_key = request.form.get('extend_key')
        extend_months_str = request.form.get('extend_months')  # '1','3','6','12'
        if extend_key and extend_months_str:
            try:
                extend_months = int(extend_months_str)
                extension_days = extend_months * 30  # 1 месяц ~ 30 дней

                role = g.user.role
                users, user_tariffs, tariffs, user_keys, miner_data = get_data_for_user(role)

                # Гарантируем наличие нужных колонок
                for col in ['email', 'phone_number', 'telegram_id']:
                    if col not in users.columns:
                        users[col] = ''

                user_keys_with_tariffs = user_keys.merge(
                    tariffs, left_on='tariff_id', right_on='tariff_id',
                    how='left', suffixes=('', '_tariffs')
                )
                merged_data_tmp = users.merge(
                    user_keys_with_tariffs, left_on='id', right_on='user_id',
                    how='left', suffixes=('', '_user_keys')
                )

                if '@' in identifier and not identifier.isdigit():
                    user_info_tmp_df = users[users['email'] == identifier]
                    if not user_info_tmp_df.empty:
                        user_info_tmp = user_info_tmp_df.iloc[0]
                        client_data_tmp = merged_data_tmp[merged_data_tmp['email'] == identifier]
                    else:
                        return "User not found", 404
                elif not users[users['phone_number'] == identifier].empty:
                    user_info_tmp_df = users[users['phone_number'] == identifier]
                    user_info_tmp = user_info_tmp_df.iloc[0]
                    client_data_tmp = merged_data_tmp[merged_data_tmp['phone_number'] == identifier]
                elif not users[users['telegram_id'] == identifier].empty:
                    user_info_tmp_df = users[users['telegram_id'] == identifier]
                    user_info_tmp = user_info_tmp_df.iloc[0]
                    client_data_tmp = merged_data_tmp[merged_data_tmp['telegram_id'] == identifier]
                else:
                    return "User not found", 404

                user_id = int(user_info_tmp['id'])
                tariff_id = 16
                amount = 0

                logging.info(f"[client_details] Пытаюсь продлить ключ: user_id={user_id}, tariff_id={tariff_id}, amount={amount}, extension_days={extension_days}, key={extend_key}")
                
                result, status_code = extend_key_subscription(
                    user_id=user_id,
                    tariff_id=tariff_id,
                    amount=amount,
                    extension_days=extension_days,
                    key=extend_key
                )

                logging.info(f"[client_details] Результат продления: status_code={status_code}, result={result}")

                if status_code == 200:
                    logging.info(f"[client_details] Создаю запись о платеже: user_id={user_id}, tariff_id={tariff_id}, amount={amount}, extension_days={extension_days}, key={extend_key}")
                    new_payment = Payment(
                        user_id=user_id,
                        tariff_id=tariff_id,
                        amount=amount,
                        extension_days=extension_days,
                        payment_id='manual_extension',
                        payment_date=datetime.now(),
                        key=extend_key,
                        processed=True
                    )
                    db.session.add(new_payment)
                    db.session.commit()
                    logging.info(f"[client_details] Запись о платеже создана с ID={new_payment.id}")
                    flash("Ключ успешно продлён", "success")
                else:
                    error_msg = result.get('message', 'Неизвестная ошибка') if isinstance(result, dict) else str(result)
                    flash(f"Ошибка при продлении: {error_msg}", "error")

            except Exception as e:
                db.session.rollback()
                logging.error(f"[client_details] Ошибка при ручном продлении: {e}", exc_info=True)
                flash(f"Ошибка при ручном продлении: {e}", "error")

        return redirect(url_for('client.client_details', identifier=identifier))

    # =========================================
    # 2) Основная логика (GET)
    # =========================================
    role = g.user.role
    users, user_tariffs, tariffs, user_keys, miner_data = get_data_for_user(role)

    # Гарантируем наличие нужных колонок
    for col in ['email', 'phone_number', 'telegram_id']:
        if col not in users.columns:
            users[col] = ''

    # Приводим все идентификаторы к строке и убираем пробелы
    identifier = str(identifier).strip()
    users['telegram_id'] = users['telegram_id'].astype(str).str.strip()
    users['phone_number'] = users['phone_number'].astype(str).str.strip()
    users['email'] = users['email'].astype(str).str.strip()

    # Удаляю отладку:
    # logging.info(f"Ищу telegram_id: '{identifier}' среди: {users['telegram_id'].tolist()}")
    # logging.info(f"users DataFrame:\n{users[['id', 'email', 'phone_number', 'telegram_id']]}")

    user_keys_with_tariffs = user_keys.merge(
        tariffs, left_on='tariff_id', right_on='tariff_id',
        how='left', suffixes=('', '_tariffs')
    )
    merged_data = users.merge(
        user_keys_with_tariffs, left_on='id', right_on='user_id',
        how='left', suffixes=('', '_user_keys')
    )

    if '@' in identifier and not identifier.isdigit():
        user_info_df = users[users['email'] == identifier]
        if not user_info_df.empty:
            user_info = user_info_df.iloc[0]
            client_data = merged_data[merged_data['email'] == identifier]
        else:
            return "User not found", 404
    elif not users[users['phone_number'] == identifier].empty:
        user_info_df = users[users['phone_number'] == identifier]
        user_info = user_info_df.iloc[0]
        client_data = merged_data[merged_data['phone_number'] == identifier]
    elif not users[users['telegram_id'] == identifier].empty:
        user_info_df = users[users['telegram_id'] == identifier]
        user_info = user_info_df.iloc[0]
        client_data = merged_data[merged_data['telegram_id'] == identifier]
    else:
        return "User not found", 404

    # Читаем платежи через SQLAlchemy как в оригинальном коде
    payments = Payment.query.all()
    payments_df = pd.DataFrame([{
        'user_id': p.user_id,
        'tariff_id': p.tariff_id,
        'amount': p.amount,
        'extension_days': p.extension_days,
        'payment_date': p.payment_date,
        'key': p.key,
        'payment_id': p.payment_id,
        'processed': p.processed
    } for p in payments])

    partners = PartnerManagerAssociation.query.all()
    managers = ManagerSupervisorAssociation.query.all()
    partner_manager_df = pd.DataFrame([{
        'partner_id': p.partner_id,
        'manager_id': p.manager_id
    } for p in partners])
    manager_supervisor_df = pd.DataFrame([{
        'manager_id': m.manager_id,
        'supervisor_id': m.supervisor_id
    } for m in managers])

    if 'hs_rt' in miner_data.columns:
        miner_data['device_info'] = miner_data.apply(lambda row: {
            'device_model': row['device_model'],
            'mhs_av': row['mhs_av'],
            'hs_rt': row['hs_rt'],
            'temperature': row['temperature'],
            'fan_speed_in': row['fan_speed_in'],
            'fan_speed_out': row['fan_speed_out'],
            'power': row['power'],
            'uptime_hours': row['uptime_hours'],
            'uptime_minutes': row['uptime_minutes'],
            'power_mode': row['power_mode'],
            'power_limit': row['power_limit'],
            'pool_url': row['pool_url'],
            'pool_user': row['pool_user'],
            'status': 'Активный' if row['status'] == 1 else 'Отключенный'
        }, axis=1)
        miner_details = miner_data.groupby(['user_id', 'key'])['device_info'].apply(list).reset_index(name='device_models')
        merged_data = merged_data.merge(miner_details, on=['user_id', 'key'], how='left')

        def sort_by_status(devices):
            if not isinstance(devices, list):
                return devices
            # 'Активный' в начале, 'Отключенный' после
            return sorted(devices, key=lambda d: 0 if d['status'] == 'Активный' else 1)

        merged_data['device_models'] = merged_data['device_models'].apply(sort_by_status)

        # Подсчёт общего числа Асиков (всех)
        merged_data['asic_count'] = merged_data['device_models'].apply(lambda x: len(x) if isinstance(x, list) else 0)
        # Подсчёт отдельно активных/неактивных
        merged_data['asic_active_count'] = merged_data['device_models'].apply(
            lambda devices: sum(d['status'] == 'Активный' for d in devices) if isinstance(devices, list) else 0
        )
        merged_data['asic_inactive_count'] = merged_data['device_models'].apply(
            lambda devices: sum(d['status'] == 'Отключенный' for d in devices) if isinstance(devices, list) else 0
        )
    else:
        merged_data['device_models'] = None
        merged_data['asic_count'] = 0
        merged_data['asic_active_count'] = 0
        merged_data['asic_inactive_count'] = 0

    def get_device_status(key):
        try:
            conn = sqlite3.connect('/root/websocket/devices_data.db')
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM device_data WHERE uid = ?", (key,))
            device_data = cursor.fetchone()
            conn.close()
            return 'Online' if device_data else 'Offline'
        except:
            return 'Unknown'

    merged_data['online_status'] = merged_data['key'].apply(get_device_status)

    if 'payment_status' not in merged_data.columns:
        merged_data['payment_status'] = 'Не оплачено'

    # После merge с тарифами явно переименовываем поле name -> tariff_name
    if 'name' in merged_data.columns:
        merged_data = merged_data.rename(columns={'name': 'tariff_name'})

    # НЕ преобразуем статус, оставляем как есть из базы
    # merged_data['status'] = merged_data['status'].apply(status_human)

    # device_models всегда список
    if 'device_models' not in merged_data.columns:
        merged_data['device_models'] = [[] for _ in range(len(merged_data))]
    else:
        merged_data['device_models'] = merged_data['device_models'].apply(lambda x: x if isinstance(x, list) else [])

    # asic_count, asic_active_count, asic_inactive_count всегда int
    for col in ['asic_count', 'asic_active_count', 'asic_inactive_count']:
        if col not in merged_data.columns:
            merged_data[col] = 0
        merged_data[col] = merged_data[col].fillna(0).astype(int)

    # online_status всегда строка
    if 'online_status' not in merged_data.columns:
        merged_data['online_status'] = 'Unknown'
    merged_data['online_status'] = merged_data['online_status'].fillna('Unknown').astype(str)

    # client_data = только по user_id
    client_data = merged_data[merged_data['user_id'] == user_info['id']]

    # История платежей: включаем все оплаты по ключам пользователя
    if not payments_df.empty and 'user_id' in payments_df.columns:
        # Получаем все ключи пользователя
        user_keys = set(client_data['key'])
        
        # Фильтруем платежи по ключам пользователя
        client_payments = payments_df[payments_df['key'].isin(user_keys)]
        
        # Добавляем пометку о том, что это оплата другого аккаунта
        if not client_payments.empty:
            client_payments = client_payments.copy()
            client_payments['payment_date'] = pd.to_datetime(client_payments['payment_date'], errors='coerce')
            client_payments['is_foreign'] = client_payments['user_id'] != user_info['id']
            client_payments = client_payments.sort_values('payment_date', ascending=False)
    else:
        client_payments = pd.DataFrame()

    partner_db_engine = create_engine('sqlite:///' + os.path.join('/root/cabinet', 'instance/users.db'))
    partner_connection = partner_db_engine.connect()
    partner_keys_query = '''
        SELECT uk.key, u.username AS partner_name
        FROM user_key AS uk
        JOIN user AS u ON uk.user_id = u.id
    '''
    partner_keys_df = pd.read_sql(partner_keys_query, partner_connection)
    partner_connection.close()

    user_keys_set = set(client_data['key'])
    partner_keys_df = partner_keys_df[partner_keys_df['key'].isin(user_keys_set)]

    return render_template('client/details.html',
                         user_info=user_info,
                         client_data=client_data,
                         client_payments=client_payments,
                         partner_keys_df=partner_keys_df,
                         identifier=identifier
    ) 