"""
Автозадания системы Sova Monitoring
Перенесены из create_summary_table.py
"""

import sqlite3
import logging
import json
import os
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.executors.pool import ThreadPoolExecutor
import pytz
import requests
import time
from flask import current_app
from ..models.user import User
from ..models.user_key import UserKey
from ..models.payment import Payment
from .. import db
import sys
import os
import json
sys.path.append('/root/cabinet')
from email_utils import send_email
from phone_utils import send_sms

logger = logging.getLogger(__name__)

class SchedulerManager:
    """Менеджер для управления автозаданиями"""
    
    def __init__(self):
        self.scheduler = None
        self.config_file = '/root/cabinet/scheduler_config.json'
        self.jobs_config = {
            'update_key_status': {
                'name': 'Обновление статуса ключей',
                'description': 'Проверяет и обновляет статус ключей каждый час',
                'function': self.update_key_status,
                'trigger': 'interval',
                'minutes': 60,
                'enabled': True,
                'autostart': True
            },
            'sync_keys': {
                'name': 'Синхронизация ключей',
                'description': 'Синхронизирует ключи с внешней базой данных каждую минуту',
                'function': self.sync_keys,
                'trigger': 'interval',
                'minutes': 1,
                'enabled': True,
                'autostart': True
            },
            'notify_user_about_key_status': {
                'name': 'Уведомления о статусе ключей',
                'description': 'Отправляет уведомления пользователям о сроке действия подписок в 19:00',
                'function': self.notify_user_about_key_status,
                'trigger': 'cron',
                'hour': 19,
                'minute': 0,
                'enabled': True,
                'autostart': True
            },
            'calculate_metrics_and_send': {
                'name': 'Ежедневный отчет',
                'description': 'Отправляет ежедневный отчет с метриками в 10:00',
                'function': self.calculate_metrics_and_send,
                'trigger': 'cron',
                'hour': 10,
                'minute': 0,
                'enabled': True,
                'autostart': True,
                'phone_numbers': ['79086640880'],  # Номера телефонов для отправки отчетов
                'greetings': ['Здравствуйте. Роман Михайлович!'],  # Приветствия для каждого номера
                'data_settings': {  # Настройки данных для включения в отчет
                    'include_activations': True,
                    'include_extensions': True,
                    'include_total_amount': True,
                    'include_usd_rate': True,
                    'include_bitcoin_price': True
                }
            }
        }
        self.logs_file = '/root/cabinet/scheduler_logs.json'
        
        # Загружаем сохраненные настройки
        self.load_config()
        
        self.init_scheduler()
        
        # Автоматический запуск автозаданий с autostart=True
        for job_id, config in self.jobs_config.items():
            if config.get('enabled', True) and config.get('autostart', True):
                try:
                    self.start_job(job_id)
                except Exception as e:
                    logger.error(f"Ошибка автозапуска задания {job_id}: {e}")
    
    def load_config(self):
        """Загрузка сохраненной конфигурации"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                    # Обновляем настройки из файла
                    for job_id, saved_settings in saved_config.items():
                        if job_id in self.jobs_config:
                            # Обновляем только настройки, не трогая function
                            for key, value in saved_settings.items():
                                if key != 'function':  # Не перезаписываем функцию
                                    self.jobs_config[job_id][key] = value
                logger.info("Конфигурация автозаданий загружена из файла")
        except Exception as e:
            logger.error(f"Ошибка загрузки конфигурации: {e}")
    
    def save_config(self):
        """Сохранение конфигурации в файл"""
        try:
            # Создаем копию конфигурации без функций для сохранения
            config_to_save = {}
            for job_id, config in self.jobs_config.items():
                config_copy = config.copy()
                if 'function' in config_copy:
                    del config_copy['function']  # Удаляем функцию, так как её нельзя сериализовать
                config_to_save[job_id] = config_copy
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_to_save, f, indent=2, ensure_ascii=False)
            logger.info("Конфигурация автозаданий сохранена в файл")
        except Exception as e:
            logger.error(f"Ошибка сохранения конфигурации: {e}")
    
    def init_scheduler(self):
        """Инициализация планировщика"""
        jobstores = {
            'default': MemoryJobStore()
        }
        executors = {
            'default': ThreadPoolExecutor(20)
        }
        job_defaults = {
            'coalesce': False,
            'max_instances': 3
        }
        
        self.scheduler = BackgroundScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone=pytz.timezone('Asia/Irkutsk')
        )
    
    def start_scheduler(self):
        """Запуск планировщика"""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("Планировщик автозаданий запущен")
    
    def stop_scheduler(self):
        """Остановка планировщика"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Планировщик автозаданий остановлен")
    
    def get_all_jobs(self):
        """Получение всех автозаданий с их статусом"""
        jobs = []
        for job_id, config in self.jobs_config.items():
            # Определяем статус задания
            is_running = self.is_job_running(job_id)
            status = 'running' if is_running else 'stopped'
            
            # Если задание отключено, показываем его как остановленное
            if not config['enabled']:
                status = 'stopped'
            
            job_info = {
                'id': job_id,
                'name': config['name'],
                'description': config['description'],
                'enabled': config['enabled'],
                'status': status,
                'next_run': self.get_next_run_time(job_id),
                'last_run': self.get_last_run_time(job_id),
                'trigger': config['trigger'],
                'minutes': config.get('minutes'),
                'hour': config.get('hour'),
                'minute': config.get('minute'),
                'autostart': config.get('autostart', True) # Добавляем поле autostart
            }
            jobs.append(job_info)
        return jobs
    
    def is_job_running(self, job_id):
        """Проверка, запущено ли автозадание"""
        return self.scheduler.get_job(job_id) is not None
    
    def get_next_run_time(self, job_id):
        """Получение времени следующего запуска"""
        job = self.scheduler.get_job(job_id)
        if job and job.next_run_time:
            return job.next_run_time.strftime('%Y-%m-%d %H:%M:%S')
        return None
    
    def get_last_run_time(self, job_id):
        """Получение времени последнего запуска"""
        # Здесь можно добавить логику для отслеживания последнего запуска
        return None
    
    def start_job(self, job_id):
        """Запуск автозадания"""
        if job_id not in self.jobs_config:
            self.log_job_event(job_id, f"Ошибка: автозадание {job_id} не найдено", 'error')
            return False
        
        config = self.jobs_config[job_id]
        if not config['enabled']:
            self.log_job_event(job_id, f"Ошибка: автозадание {job_id} отключено", 'error')
            return False
        
        try:
            # Проверяем, что планировщик запущен
            if not self.scheduler.running:
                self.scheduler.start()
                logger.info("Планировщик запущен")
            
            if config['trigger'] == 'interval':
                self.scheduler.add_job(
                    config['function'],
                    trigger=config['trigger'],
                    minutes=config['minutes'],
                    id=job_id,
                    replace_existing=True
                )
                self.log_job_event(job_id, f"Автозадание запущено с интервалом {config['minutes']} минут", 'info')
            elif config['trigger'] == 'cron':
                self.scheduler.add_job(
                    config['function'],
                    trigger=config['trigger'],
                    hour=config['hour'],
                    minute=config['minute'],
                    id=job_id,
                    replace_existing=True
                )
                self.log_job_event(job_id, f"Автозадание запущено по расписанию {config['hour']}:{config['minute']}", 'info')
            
            logger.info(f"Автозадание {job_id} запущено")
            return True
        except Exception as e:
            error_msg = f"Ошибка запуска: {str(e)}"
            self.log_job_event(job_id, error_msg, 'error')
            logger.error(f"Ошибка запуска автозадания {job_id}: {e}")
            return False
    
    def stop_job(self, job_id):
        """Остановка автозадания"""
        try:
            self.scheduler.remove_job(job_id)
            self.log_job_event(job_id, "Автозадание остановлено", 'info')
            logger.info(f"Автозадание {job_id} остановлено")
            return True
        except Exception as e:
            self.log_job_event(job_id, f"Ошибка остановки: {str(e)}", 'error')
            logger.error(f"Ошибка остановки автозадания {job_id}: {e}")
            return False
    
    def run_job_now(self, job_id):
        """Запуск автозадания немедленно"""
        if job_id not in self.jobs_config:
            return False
        
        try:
            config = self.jobs_config[job_id]
            self.log_job_event(job_id, "Автозадание запущено немедленно", 'info')
            config['function']()
            self.log_job_event(job_id, "Автозадание выполнено немедленно", 'info')
            logger.info(f"Автозадание {job_id} выполнено немедленно")
            return True
        except Exception as e:
            self.log_job_event(job_id, f"Ошибка выполнения: {str(e)}", 'error')
            logger.error(f"Ошибка выполнения автозадания {job_id}: {e}")
            return False
    
    def get_status(self):
        """Получение статуса всех автозаданий"""
        return {
            'scheduler_running': self.scheduler.running,
            'jobs': self.get_all_jobs()
        }
    
    def log_job_event(self, job_id, message, level='info'):
        """Логирование событий автозадания"""
        try:
            logs = []
            if os.path.exists(self.logs_file):
                with open(self.logs_file, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'job_id': job_id,
                'message': message,
                'level': level
            }
            
            logs.append(log_entry)
            
            # Оставляем только последние 100 записей для каждого задания
            job_logs = [log for log in logs if log['job_id'] == job_id]
            if len(job_logs) > 100:
                other_logs = [log for log in logs if log['job_id'] != job_id]
                job_logs = job_logs[-100:]
                logs = other_logs + job_logs
            
            with open(self.logs_file, 'w', encoding='utf-8') as f:
                json.dump(logs, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            logger.error(f"Ошибка записи лога: {e}")
    
    def get_job_logs(self, job_id):
        """Получение логов автозадания"""
        try:
            if not os.path.exists(self.logs_file):
                return []
            
            with open(self.logs_file, 'r', encoding='utf-8') as f:
                logs = json.load(f)
            
            # Фильтруем логи для конкретного задания
            job_logs = [log for log in logs if log['job_id'] == job_id]
            
            # Возвращаем последние 20 записей
            return job_logs[-20:]
            
        except Exception as e:
            logger.error(f"Ошибка получения логов для {job_id}: {e}")
            return []
    
    def get_job_config(self, job_id):
        """Получение конфигурации автозадания"""
        if job_id not in self.jobs_config:
            return None
        
        config = self.jobs_config[job_id].copy()
        
        # Удаляем поле function, так как оно не сериализуется
        if 'function' in config:
            del config['function']
        
        config['id'] = job_id
        config['status'] = 'running' if self.is_job_running(job_id) else 'stopped'
        config['next_run'] = self.get_next_run_time(job_id)
        
        return config
    
    def update_job_config(self, job_id, data):
        """Обновление конфигурации автозадания"""
        if job_id not in self.jobs_config:
            return False
        
        try:
            config = self.jobs_config[job_id]
            
            # Обновляем основные параметры
            if 'name' in data:
                config['name'] = data['name']
            if 'description' in data:
                config['description'] = data['description']
            if 'enabled' in data:
                config['enabled'] = data['enabled']
            
            # Обновляем параметры запуска
            if 'trigger' in data:
                config['trigger'] = data['trigger']
                
                if data['trigger'] == 'interval':
                    if 'minutes' in data:
                        config['minutes'] = int(data['minutes'])
                elif data['trigger'] == 'cron':
                    if 'hour' in data:
                        config['hour'] = int(data['hour'])
                    if 'minute' in data:
                        config['minute'] = int(data['minute'])
            
            # Обновляем autostart
            if 'autostart' in data:
                config['autostart'] = data['autostart']
            
            # Обновляем специальные настройки для calculate_metrics_and_send
            if job_id == 'calculate_metrics_and_send':
                if 'phone_numbers' in data:
                    config['phone_numbers'] = data['phone_numbers']
                if 'greetings' in data:
                    config['greetings'] = data['greetings']
                if 'data_settings' in data:
                    config['data_settings'] = data['data_settings']
            
            # Если задание активно, перезапускаем его с новыми параметрами
            if self.is_job_running(job_id):
                self.stop_job(job_id)
                if config['enabled']:
                    self.start_job(job_id)
            
            # Сохраняем обновленную конфигурацию в файл
            self.save_config()
            
            logger.info(f"Конфигурация автозадания {job_id} обновлена")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка обновления конфигурации {job_id}: {e}")
            return False
    
    # Автозадания (перенесены из create_summary_table.py)
    
    def update_key_status(self):
        """Обновление статуса ключей"""
        job_id = 'update_key_status'
        self.log_job_event(job_id, "Запуск обновления статуса ключей")
        logger.info("Запуск обновления статуса ключей")
        
        try:
            conn = sqlite3.connect('/root/miner-data/file.db')
            cursor = conn.cursor()
            current_time = datetime.now()
            
            cursor.execute("SELECT id, key_name, end_date FROM user_keys WHERE status != 'inactive'")
            keys = cursor.fetchall()

            updated_count = 0
            for key in keys:
                key_id = key[0]
                key_name = key[1]
                end_date_str = key[2]

                if end_date_str is None:
                    continue

                end_date = datetime.strptime(end_date_str, '%Y-%m-%d %H:%M:%S')

                if end_date < current_time:
                    new_key_name = f"(OFF) {key_name}" if not key_name.startswith("(OFF)") else key_name
                    logger.info(f"Префикс (OFF) для ключа ID {key_id}: старое имя '{key_name}', новое имя '{new_key_name}'")
                    cursor.execute("UPDATE user_keys SET status=?, key_name=? WHERE id=?", ('inactive', new_key_name, key_id))
                    logger.info(f"Key ID {key_id}: статус обновлен на 'inactive', имя ключа обновлено на '{new_key_name}'")
                    updated_count += 1
            
            conn.commit()
            conn.close()
            self.log_job_event(job_id, f"Обновление статуса ключей завершено. Обновлено ключей: {updated_count}")
            logger.info("Обновление статуса ключей завершено")
            
        except Exception as e:
            self.log_job_event(job_id, f"Ошибка при обновлении статуса ключей: {e}", 'error')
            logger.error(f"Ошибка при обновлении статуса ключей: {e}")
    
    def sync_keys(self):
        """Синхронизация ключей с внешней базой"""
        job_id = 'sync_keys'
        self.log_job_event(job_id, "Запуск синхронизации ключей")
        logger.info("Запуск синхронизации ключей")
        
        try:
            # Создаем контекст приложения для работы с Flask
            from flask import current_app
            from app import create_app
            
            # Создаем приложение, если контекста нет
            try:
                app = current_app._get_current_object()
            except RuntimeError:
                app = create_app()
            
            with app.app_context():
                conn = sqlite3.connect('/root/miner-data/file.db')
                cursor = conn.cursor()

                # Проверяем структуру таблицы user_keys
                cursor.execute("PRAGMA table_info(user_keys)")
                table_info = cursor.fetchall()
                logger.info(f"Структура таблицы user_keys: {table_info}")

                user_keys = UserKey.query.all()
                logger.info(f"Найдено ключей в локальной базе: {len(user_keys)}")
                synced_count = 0
                not_found_count = 0
                updated_count = 0

                for user_key in user_keys:
                    cursor.execute("SELECT status, start_date, end_date, tariff_id FROM user_keys WHERE key=?", (user_key.key,))
                    result = cursor.fetchone()
                    if result:
                        previous_end_date = datetime.strptime(user_key.end_date, '%Y-%m-%d %H:%M:%S') if user_key.end_date else None
                        old_status = user_key.status
                        old_start_date = user_key.start_date
                        old_end_date = user_key.end_date
                        old_tariff_id = user_key.tariff_id
                        
                        # Обновляем данные
                        user_key.status = result[0]
                        user_key.start_date = result[1]
                        user_key.end_date = result[2]
                        user_key.tariff_id = result[3]
                        
                        # Проверяем, были ли изменения
                        if (old_status != user_key.status or 
                            old_start_date != user_key.start_date or 
                            old_end_date != user_key.end_date or 
                            old_tariff_id != user_key.tariff_id):
                            updated_count += 1
                            logger.info(f"Ключ {user_key.key}: обновлен - статус: {old_status}->{user_key.status}, дата окончания: {old_end_date}->{user_key.end_date}")
                        
                        db.session.commit()
                        synced_count += 1

                        # Здесь можно добавить вызов handle_status_change если нужно

                        if user_key.end_date:
                            new_end_date = datetime.strptime(user_key.end_date, '%Y-%m-%d %H:%M:%S')
                            if previous_end_date and new_end_date > previous_end_date and new_end_date > datetime.now():
                                # Здесь можно добавить вызов calculate_earnings если нужно
                                pass
                    else:
                        not_found_count += 1
                        logger.warning(f"Ключ {user_key.key} не найден во внешней базе данных")

                conn.close()
                self.log_job_event(job_id, f"Синхронизация ключей завершена. Обработано: {len(user_keys)}, синхронизировано: {synced_count}, обновлено: {updated_count}, не найдено: {not_found_count}")
                logger.info(f"Синхронизация ключей завершена. Обработано: {len(user_keys)}, синхронизировано: {synced_count}, обновлено: {updated_count}, не найдено: {not_found_count}")
                
        except Exception as e:
            self.log_job_event(job_id, f"Ошибка при синхронизации ключей: {e}", 'error')
            logger.error(f"Ошибка при синхронизации ключей: {e}")
            import traceback
            logger.error(f"Полная ошибка: {traceback.format_exc()}")
    
    def notify_user_about_key_status(self):
        """Уведомления пользователей о статусе ключей"""
        job_id = 'notify_user_about_key_status'
        self.log_job_event(job_id, "Начало проверки сроков действия подписок для отправки уведомлений...")
        logger.info("Начало проверки сроков действия подписок для отправки уведомлений...")

        try:
            # Создаем контекст приложения для работы с Flask
            from flask import current_app
            app = current_app._get_current_object()
            
            with app.app_context():
                conn = sqlite3.connect('/root/miner-data/file.db')
                cursor = conn.cursor()

                current_date = datetime.now().date()

                cursor.execute("""
                    SELECT k.id, k.user_id, k.key, k.end_date, u.email, u.phone_number, k.last_notification
                    FROM user_keys k
                    JOIN users u ON k.user_id = u.id
                    WHERE k.status IN ('active', 'new', 'inactive')
                """)

                keys = cursor.fetchall()
                logger.info(f"Найдено подписок: {len(keys)} для проверки")

                if not keys:
                    self.log_job_event(job_id, "Нет подписок для уведомления")
                    logger.info("Нет подписок для уведомления")
                    return

                notifications_sent = 0
                for key in keys:
                    key_id = key[0]
                    key_value = key[2]
                    end_date_str = key[3]
                    email = key[4]
                    phone_number = key[5]
                    last_notification_str = key[6]

                    if not end_date_str:
                        logger.warning(f"Подписка с ключом {key_value} не имеет даты окончания.")
                        continue

                    end_date = datetime.strptime(end_date_str, '%Y-%m-%d %H:%M:%S').date()
                    remaining_days = (end_date - current_date).days

                    if last_notification_str:
                        last_notification = datetime.strptime(last_notification_str, '%Y-%m-%d').date()
                        if last_notification == current_date:
                            logger.info(f"Подписка с ключом {key_value} проверена. Уведомление не требуется, до окончания осталось {remaining_days} дней.")
                            continue

                    if remaining_days == 5:
                        self.send_notification(key_value, email, phone_number, f"Подписка для устройства {key_value} истекает через 5 дней.", include_link=True)
                        logger.info(f"Уведомление отправлено для ключа {key_value}. До окончания действия осталось 5 дней.")
                        notifications_sent += 1
                    elif remaining_days == 2:
                        self.send_notification(key_value, email, phone_number, f"Подписка для устройства {key_value} истекает через 2 дня.", include_link=False)
                        logger.info(f"Уведомление отправлено для ключа {key_value}. До окончания действия осталось 2 дня.")
                        notifications_sent += 1
                    elif remaining_days == 0:
                        self.send_notification(key_value, email, phone_number, f"Подписка для устройства {key_value} истекла. Доступ приостановлен.", include_link=False)
                        logger.info(f"Уведомление отправлено для ключа {key_value}. Подписка истекла сегодня.")
                        notifications_sent += 1
                    else:
                        logger.info(f"Подписка с ключом {key_value} проверена. Уведомление уже было отправлено сегодня.")

                    cursor.execute("""
                        UPDATE user_keys
                        SET last_notification = ?
                        WHERE id = ?
                    """, (current_date, key_id))
                    conn.commit()

                self.log_job_event(job_id, f"Проверка уведомлений завершена. Отправлено уведомлений: {notifications_sent}")

        except Exception as e:
            self.log_job_event(job_id, f"Ошибка при отправке уведомлений: {e}", 'error')
            logger.error(f"Ошибка при отправке уведомлений: {e}")
        finally:
            if 'conn' in locals():
                cursor.close()
                conn.close()
    
    def send_notification(self, key_value, email, phone_number, message, include_link=False):
        """Отправка уведомлений"""
        logger.info(f"Отправка уведомлений для подписки устройства с уникальным номером {key_value}: {message}")

        # Отправляем SMS
        sms_message = message
        if include_link:
            sms_message += f" Продлить доступ: https://cabinet.sovamonitoring.com/pay?key={key_value}"
        
        if send_sms(phone_number, sms_message):
            logger.info(f"SMS успешно отправлено на {phone_number}")
        else:
            logger.error(f"Ошибка отправки SMS на {phone_number}")

        # Отправляем Email
        email_message = f"{message} Продлите доступ на сайте: https://cabinet.sovamonitoring.com/pay?key={key_value}"
        if send_email(email, f"Уведомление о подписке устройства {key_value}", email_message):
            logger.info(f"Email успешно отправлено на {email}")
        else:
            logger.error(f"Ошибка отправки email на {email}")
    
    def fetch_usd_to_rub_exchange_rate(self):
        """Получение курса обмена USD на RUB"""
        url = "https://open.er-api.com/v6/latest/USD"
        for _ in range(5):
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()
                rate = float(data.get("rates", {}).get("RUB", 0.0))
                return rate
            except requests.RequestException:
                time.sleep(5)
        return None

    def fetch_bitcoin_info(self):
        """Получение информации о Bitcoin"""
        coin_id = '1-bitcoin-sha-256'
        url = f'https://whattomine.com/coins/{coin_id}.json'
        for _ in range(5):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                }
                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                data = response.json()
                return data
            except requests.RequestException:
                time.sleep(5)
            except ValueError:
                return {}
        return None

    def calculate_metrics_and_send(self):
        """Расчет метрик и отправка отчета"""
        job_id = 'calculate_metrics_and_send'
        self.log_job_event(job_id, "Запуск расчета метрик и отправки отчета")
        logger.info("Запуск расчета метрик и отправки отчета")
        
        try:
            # Установка временной зоны Иркутска
            irkutsk_tz = pytz.timezone("Asia/Irkutsk")
            now = datetime.now(irkutsk_tz)
            one_day_ago = now - timedelta(days=1)

            # Подключение к базам данных
            activations_conn = sqlite3.connect('/root/miner-data/file.db')
            payments_conn = sqlite3.connect('/root/cabinet/instance/users.db')

            try:
                # Подсчет активаций за последние 24 часа
                activations_cursor = activations_conn.cursor()
                activations_cursor.execute(
                    """
                    SELECT COUNT(*)
                    FROM user_keys
                    WHERE status = 'active' AND DATETIME(start_date) >= ? AND DATETIME(start_date) <= ?
                    """,
                    (one_day_ago.strftime('%Y-%m-%d %H:%M:%S'), now.strftime('%Y-%m-%d %H:%M:%S'))
                )
                activation_count = activations_cursor.fetchone()[0]

                # Подсчет продлений за последние 24 часа
                payments_cursor = payments_conn.cursor()
                payments_cursor.execute(
                    """
                    SELECT COUNT(*), SUM(amount)
                    FROM payment
                    WHERE processed = 1 AND DATETIME(payment_date) >= ? AND DATETIME(payment_date) <= ?
                    """,
                    (one_day_ago.strftime('%Y-%m-%d %H:%M:%S'), now.strftime('%Y-%m-%d %H:%M:%S'))
                )
                extensions_count, total_amount = payments_cursor.fetchone()

                # Проверка на None
                total_amount = total_amount if total_amount is not None else 0

                # Получение курса USD и Bitcoin
                usd_to_rub_rate = self.fetch_usd_to_rub_exchange_rate()
                bitcoin_info = self.fetch_bitcoin_info()
                bitcoin_price = bitcoin_info.get('exchange_rate', 'неизвестно')

                # Формирование сообщения
                message = (
                    f"Здравствуйте. Роман Михайлович!\n"
                    f"Отчет за последние 24 часа:\n"
                    f"Количество активаций: {activation_count}\n"
                    f"Количество продлений: {extensions_count}\n"
                    f"Общая сумма продлений: {total_amount} руб.\n"
                    f"Курс USD к RUB: {usd_to_rub_rate if usd_to_rub_rate else 'не удалось получить'}\n"
                    f"Курс Bitcoin: {bitcoin_price}"
                )

                # Получаем настройки для отправки
                config = self.jobs_config[job_id]
                phone_numbers = config.get('phone_numbers', ['79086640880'])
                greetings = config.get('greetings', ['Здравствуйте. Роман Михайлович!'])
                data_settings = config.get('data_settings', {
                    'include_activations': True,
                    'include_extensions': True,
                    'include_total_amount': True,
                    'include_usd_rate': True,
                    'include_bitcoin_price': True
                })
                
                # Формируем сообщение с учетом настроек
                message_parts = []
                
                # Добавляем приветствие (берем первое, если приветствий меньше чем номеров)
                greeting = greetings[0] if greetings else 'Здравствуйте. Роман Михайлович!'
                message_parts.append(f"{greeting}")
                message_parts.append("Отчет за последние 24 часа:")
                
                # Добавляем данные согласно настройкам
                if data_settings.get('include_activations', True):
                    message_parts.append(f"Количество активаций: {activation_count}")
                
                if data_settings.get('include_extensions', True):
                    message_parts.append(f"Количество продлений: {extensions_count}")
                
                if data_settings.get('include_total_amount', True):
                    message_parts.append(f"Общая сумма продлений: {total_amount} руб.")
                
                if data_settings.get('include_usd_rate', True):
                    usd_rate_text = f"Курс USD к RUB: {usd_to_rub_rate if usd_to_rub_rate else 'не удалось получить'}"
                    message_parts.append(usd_rate_text)
                
                if data_settings.get('include_bitcoin_price', True):
                    bitcoin_text = f"Курс Bitcoin: {bitcoin_price}"
                    message_parts.append(bitcoin_text)
                
                full_message = '\n'.join(message_parts)
                
                # Отправляем сообщение на каждый номер с соответствующим приветствием
                for i, phone_number in enumerate(phone_numbers):
                    if i < len(greetings):
                        # Используем соответствующее приветствие
                        personal_message = full_message.replace(greeting, greetings[i])
                    else:
                        # Используем первое приветствие, если приветствий меньше чем номеров
                        personal_message = full_message
                    
                    if send_sms(phone_number, personal_message):
                        logger.info(f"Отчет успешно отправлен на номер {phone_number}")
                    else:
                        logger.error(f"Ошибка отправки отчета на номер {phone_number}")
                
                self.log_job_event(job_id, f"Ежедневный отчет отправлен на {len(phone_numbers)} номер(ов). Активаций: {activation_count}, продлений: {extensions_count}, сумма: {total_amount} руб.")
                logger.info("Ежедневный отчет отправлен")

            finally:
                # Закрытие соединений
                activations_conn.close()
                payments_conn.close()

        except Exception as e:
            self.log_job_event(job_id, f"Ошибка при выполнении расчета метрик: {e}", 'error')
            logger.error(f"Ошибка при выполнении расчета метрик: {e}") 