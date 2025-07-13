#!/usr/bin/env python3
"""
Скрипт для миграций базы данных
"""

import os
import sys
from flask_migrate import upgrade, init, migrate
from app import create_app, db

def run_migrations():
    """Запуск миграций"""
    app = create_app()
    
    with app.app_context():
        # Создаем папку migrations если её нет
        if not os.path.exists('migrations'):
            print("Инициализация миграций...")
            init()
        
        # Создаем миграцию
        print("Создание миграции...")
        migrate(message="Initial migration")
        
        # Применяем миграции
        print("Применение миграций...")
        upgrade()
        
        print("Миграции завершены успешно!")

if __name__ == '__main__':
    run_migrations() 