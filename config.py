import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Основные настройки
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    
    # База данных
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'users.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT настройки
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # YooKassa настройки
    YOOKASSA_SHOP_ID = os.environ.get('YOOKASSA_SHOP_ID') or 'your-shop-id'
    YOOKASSA_SECRET_KEY = os.environ.get('YOOKASSA_SECRET_KEY') or 'your-secret-key'
    
    # Пути к базам данных
    READ_DB_PATH = os.environ.get('READ_DB_PATH') or os.path.join(BASE_DIR, 'data', 'device_data.db')
    WRITE_DB_PATH = os.environ.get('WRITE_DB_PATH') or os.path.join(BASE_DIR, 'data', 'device_data_write.db')
    
    # Настройки приложения
    APP_PORT = int(os.environ.get('APP_PORT', 5001))
    APP_HOST = os.environ.get('APP_HOST', '0.0.0.0')
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Настройки логирования
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/app.log')
    
    # Настройки уведомлений
    NOTIFICATION_ENABLED = os.environ.get('NOTIFICATION_ENABLED', 'True').lower() == 'true'
    
    # Настройки синхронизации
    SYNC_INTERVAL = int(os.environ.get('SYNC_INTERVAL', 300))  # 5 минут
    
    # Настройки платежей
    PAYMENT_SUCCESS_URL = os.environ.get('PAYMENT_SUCCESS_URL') or 'http://localhost:5001/payment_success'
    PAYMENT_FAIL_URL = os.environ.get('PAYMENT_FAIL_URL') or 'http://localhost:5001/payment_fail' 