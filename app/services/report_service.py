from app import db
from app.models.user import User
from app.models.user_key import UserKey
from app.models.payment import Payment
from app.models.earning import Earning
from datetime import datetime, timedelta
import pandas as pd
import sqlite3

class ReportService:
    """Сервис для работы с отчётами"""
    
    @staticmethod
    def get_daily_metrics():
        """Получение ежедневных метрик"""
        try:
            conn_main = sqlite3.connect('/root/websocket/devices_data.db')
            conn_secondary = sqlite3.connect('/root/websocket/secondary_data.db')
            
            today = datetime.now().date()
            yesterday = today - timedelta(days=1)
            
            # Получение данных из daily_metrics
            query = '''
            SELECT date, total_ltc_hashrate, total_btc_hashrate, total_ltc_devices, total_btc_devices, total_keys
            FROM daily_metrics
            WHERE date IN (?, ?)
            '''
            df = pd.read_sql_query(query, conn_main, params=[str(yesterday), str(today)])
            df['date'] = pd.to_datetime(df['date']).dt.date
            
            # Подсчёт активаций на основе start_date в user_keys
            activations_today = conn_secondary.execute(
                "SELECT COUNT(*) FROM user_keys WHERE DATE(start_date) = ?", (today,)
            ).fetchone()[0]
            
            activations_yesterday = conn_secondary.execute(
                "SELECT COUNT(*) FROM user_keys WHERE DATE(start_date) = ?", (yesterday,)
            ).fetchone()[0]
            
            # Формируем метрики
            metrics = {
                'labels': ['Хэшрейт LTC', 'Хэшрейт BTC', 'Асики LTC', 'Асики BTC', 'Всего устройств', 'Активации'],
                'today': df[df['date'] == today].sum(numeric_only=True).fillna(0).tolist() + [activations_today],
                'yesterday': df[df['date'] == yesterday].sum(numeric_only=True).fillna(0).tolist() + [activations_yesterday],
                'growth': []
            }
            
            for today_val, yesterday_val in zip(metrics['today'], metrics['yesterday']):
                if yesterday_val > 0:
                    metrics['growth'].append(round(((today_val - yesterday_val) / yesterday_val) * 100, 2))
                else:
                    metrics['growth'].append(0)
            
            conn_main.close()
            conn_secondary.close()
            
            return metrics
            
        except Exception as e:
            print(f"Error getting daily metrics: {e}")
            return None
    
    @staticmethod
    def get_partner_statistics(start_date=None, end_date=None, selected_partner=None):
        """Получение статистики партнёров"""
        try:
            conn = sqlite3.connect('/root/websocket/secondary_data.db')
            
            # Если даты не указаны, выбираем последние 7 дней
            if not start_date or not end_date:
                today_date = datetime.now().date()
                end_date = today_date.isoformat()
                start_date = (today_date - timedelta(days=6)).isoformat()
            
            # Если параметр партнёра пришёл в виде списка – берём первый элемент
            if isinstance(selected_partner, list):
                selected_partner = selected_partner[0]
            
            # Запрос для статистики за выбранный период
            query_period = '''
            SELECT u.username AS partner_name,
                   DATE(k.start_date) AS activation_date,
                   COUNT(k.id) AS activated_devices
            FROM user_keys k
            LEFT JOIN user u ON k.user_id = u.id
            WHERE k.status IN ('active', 'inactive')
              AND DATE(k.start_date) BETWEEN ? AND ?
            GROUP BY u.username, DATE(k.start_date)
            ORDER BY u.username, DATE(k.start_date)
            '''
            params = [start_date, end_date]
            stats_period = pd.read_sql_query(query_period, conn, params=params)
            stats_period['activation_date'] = pd.to_datetime(stats_period['activation_date']).dt.strftime('%d.%m.%y')
            
            # Фильтрация по партнёру, если выбран конкретный
            if selected_partner and selected_partner != "all":
                stats_period = stats_period[stats_period['partner_name'] == selected_partner]
            
            # Формирование списка партнёров (только тех, у кого есть активации за период)
            partners = stats_period['partner_name'].unique().tolist()
            
            # Подсчёт статистики за выбранный период и за сегодня
            today_str = datetime.now().strftime('%d.%m.%y')
            period_stats = {}
            today_stats = {}
            partner_details = {}
            for partner in partners:
                df_partner = stats_period[stats_period['partner_name'] == partner]
                period_total = df_partner['activated_devices'].sum() if not df_partner.empty else 0
                period_stats[partner] = period_total
                
                df_today = df_partner[df_partner['activation_date'] == today_str]
                today_count = df_today['activated_devices'].sum() if not df_today.empty else 0
                today_stats[partner] = today_count
                
                details = (df_partner[['activation_date', 'activated_devices']]
                           .drop_duplicates().to_dict('records')
                           if not df_partner.empty else [])
                partner_details[partner] = details
            
            conn.close()
            
            return {
                'partners': partners,
                'period_stats': period_stats,
                'today_stats': today_stats,
                'partner_details': partner_details,
                'start_date': start_date,
                'end_date': end_date,
                'selected_partner': selected_partner
            }
            
        except Exception as e:
            print(f"Error getting partner statistics: {e}")
            return None
    
    @staticmethod
    def get_partner_statistics_all_time():
        """Получение статистики партнёров за всё время"""
        try:
            conn = sqlite3.connect('/root/websocket/secondary_data.db')
            
            # Запрос для статистики за всё время
            query_all_time = '''
            SELECT u.username AS partner_name,
                   COUNT(k.id) AS total_devices,
                   COUNT(CASE WHEN k.status = 'active' THEN 1 END) AS active_devices,
                   COUNT(CASE WHEN k.status = 'inactive' THEN 1 END) AS inactive_devices
            FROM user_keys k
            LEFT JOIN user u ON k.user_id = u.id
            WHERE k.status IN ('active', 'inactive')
            GROUP BY u.username
            ORDER BY total_devices DESC
            '''
            
            stats_all_time = pd.read_sql_query(query_all_time, conn)
            
            # Подсчёт общей статистики
            total_devices = stats_all_time['total_devices'].sum()
            total_active = stats_all_time['active_devices'].sum()
            total_inactive = stats_all_time['inactive_devices'].sum()
            
            conn.close()
            
            return {
                'stats_all_time': stats_all_time.to_dict('records'),
                'total_devices': total_devices,
                'total_active': total_active,
                'total_inactive': total_inactive
            }
            
        except Exception as e:
            print(f"Error getting all-time statistics: {e}")
            return None
    
    @staticmethod
    def get_money_table():
        """Получение данных для таблицы денежных операций"""
        try:
            conn = sqlite3.connect('/root/websocket/secondary_data.db')
            
            # Получение данных о платежах
            query = '''
            SELECT p.*, u.username, t.name as tariff_name
            FROM payment p
            LEFT JOIN user u ON p.user_id = u.id
            LEFT JOIN tariff t ON p.tariff_id = t.id
            ORDER BY p.payment_date DESC
            '''
            
            payments_df = pd.read_sql_query(query, conn)
            
            # Подсчёт общей статистики
            total_amount = payments_df['amount'].sum()
            total_processed = payments_df[payments_df['processed'] == True]['amount'].sum()
            total_pending = payments_df[payments_df['processed'] == False]['amount'].sum()
            
            conn.close()
            
            return {
                'payments': payments_df.to_dict('records'),
                'total_amount': total_amount,
                'total_processed': total_processed,
                'total_pending': total_pending
            }
            
        except Exception as e:
            print(f"Error getting money table: {e}")
            return None 