#!/usr/bin/env python3
"""
Сова Мониторинг - Система управления майнинг-устройствами
Основной файл для запуска приложения
"""

import os
import sys
import logging
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def main():
    """
    Основная функция запуска приложения
    """
    try:
        logger.info("Запуск приложения Сова Мониторинг...")
        
        # Проверяем наличие необходимых файлов
        required_files = [
            'app/__init__.py',
            'config.py'
        ]
        
        for file_path in required_files:
            if not os.path.exists(file_path):
                logger.error(f"Файл {file_path} не найден!")
                return 1
        
        # Создаём папку instance если её нет
        if not os.path.exists('instance'):
            os.makedirs('instance')
            logger.info("Создана папка instance")
        
        # Импортируем и запускаем приложение
        from app import create_app
        app = create_app()
        
        logger.info("Приложение успешно инициализировано")
        logger.info("Сервер запускается на http://0.0.0.0:5023")
        
        # Запускаем приложение
        app.run(
            host='0.0.0.0',
            port=5023,
            debug=False,
            threaded=True
        )
        
    except KeyboardInterrupt:
        logger.info("Приложение остановлено пользователем")
        return 0
    except Exception as e:
        logger.error(f"Ошибка запуска приложения: {e}")
        return 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code) 