import sqlite3
import pandas as pd
from datetime import datetime
from app.utils.helpers import parse_date

class ClientService:
    def __init__(self):
        self.file_db_path = '/root/miner-data/file.db'
        self.users_db_path = '/root/cabinet/instance/users.db'
    
    def get_client_by_identifier(self, identifier):
        """Получение клиента по идентификатору (email, phone, telegram_id)"""
        try:
            conn = sqlite3.connect(self.file_db_path)
            
            # Ищем пользователя по email, phone_number или telegram_id
            query = """
            SELECT id, email, phone_number, telegram_id 
            FROM users 
            WHERE email = ? OR phone_number = ? OR telegram_id = ?
            """
            
            user_data = pd.read_sql_query(query, conn, params=[identifier, identifier, identifier])
            conn.close()
            
            if user_data.empty:
                return None
            
            # Добавляем роль по умолчанию
            user_dict = user_data.iloc[0].to_dict()
            user_dict['role'] = 'user'  # По умолчанию роль user
            
            return user_dict
            
        except Exception as e:
            print(f"Error getting client: {e}")
            return None
    
    def get_client_keys(self, user_id):
        """Получение ключей клиента"""
        try:
            conn = sqlite3.connect(self.file_db_path)
            
            query = """
            SELECT uk.key, uk.key_name, uk.status, uk.start_date, uk.end_date, 
                   t.name as tariff_name
            FROM user_keys uk
            LEFT JOIN tariffs t ON uk.tariff_id = t.id
            WHERE uk.user_id = ?
            """
            
            keys_data = pd.read_sql_query(query, conn, params=[user_id])
            conn.close()
            
            return keys_data.to_dict('records')
            
        except Exception as e:
            print(f"Error getting client keys: {e}")
            return []
    
    def get_client_devices(self, user_id):
        """Получение устройств клиента"""
        try:
            conn = sqlite3.connect(self.file_db_path)
            
            query = """
            SELECT md.key, md.miner_ip, md.device_model, md.mhs_av, md.hs_rt, 
                   md.temperature, md.fan_speed_in, md.fan_speed_out, md.power, 
                   md.uptime_hours, md.uptime_minutes, md.power_mode, md.power_limit, 
                   md.pool_url, md.pool_user, md.status
            FROM miner_data md
            INNER JOIN user_keys uk ON md.key = uk.key
            WHERE uk.user_id = ?
            """
            
            devices_data = pd.read_sql_query(query, conn, params=[user_id])
            conn.close()
            
            return devices_data.to_dict('records')
            
        except Exception as e:
            print(f"Error getting client devices: {e}")
            return []
    
    def get_client_payments(self, user_id):
        """Получение платежей клиента из users.db"""
        try:
            conn = sqlite3.connect(self.users_db_path)
            
            query = """
            SELECT p.amount, p.extension_days, p.payment_date, p.key, p.payment_id, p.processed
            FROM payment p
            WHERE p.user_id = ?
            ORDER BY p.payment_date DESC
            """
            
            payments_data = pd.read_sql_query(query, conn, params=[user_id])
            conn.close()
            
            # Преобразуем даты
            if not payments_data.empty and 'payment_date' in payments_data.columns:
                payments_data['payment_date'] = pd.to_datetime(payments_data['payment_date'])
            
            return payments_data.to_dict('records')
            
        except Exception as e:
            print(f"Error getting client payments: {e}")
            return []
    
    def get_partner_keys(self, user_id):
        """Получение ключей партнера"""
        try:
            conn = sqlite3.connect(self.file_db_path)
            
            # Получаем всех пользователей, связанных с партнером
            query = """
            SELECT u.id, u.email, u.phone_number, u.telegram_id
            FROM users u
            WHERE u.id IN (
                SELECT DISTINCT uk.user_id 
                FROM user_keys uk 
                WHERE uk.user_id IN (
                    SELECT DISTINCT user_id FROM user_keys WHERE user_id IN (
                        SELECT id FROM users
                    )
                )
            )
            """
            
            partner_users = pd.read_sql_query(query, conn)
            conn.close()
            
            return partner_users.to_dict('records')
            
        except Exception as e:
            print(f"Error getting partner keys: {e}")
            return []
    
    def extend_key_manually(self, user_id, key, extension_days, amount):
        """Ручное продление ключа"""
        try:
            conn = sqlite3.connect(self.file_db_path)
            
            # Получаем текущую дату окончания
            query = "SELECT end_date FROM user_keys WHERE key = ? AND user_id = ?"
            current_data = pd.read_sql_query(query, conn, params=[key, user_id])
            
            if current_data.empty:
                conn.close()
                return False, "Ключ не найден"
            
            current_end_date = current_data.iloc[0]['end_date']
            
            # Вычисляем новую дату окончания
            if current_end_date and current_end_date != 'N/A':
                try:
                    current_date = pd.to_datetime(current_end_date)
                    new_end_date = current_date + pd.Timedelta(days=extension_days)
                except:
                    new_end_date = datetime.now() + pd.Timedelta(days=extension_days)
            else:
                new_end_date = datetime.now() + pd.Timedelta(days=extension_days)
            
            # Обновляем дату окончания
            update_query = "UPDATE user_keys SET end_date = ? WHERE key = ? AND user_id = ?"
            conn.execute(update_query, [new_end_date.strftime('%Y-%m-%d %H:%M:%S'), key, user_id])
            conn.commit()
            conn.close()
            
            return True, "Ключ успешно продлен"
            
        except Exception as e:
            print(f"Error extending key: {e}")
            return False, f"Ошибка при продлении: {str(e)}" 