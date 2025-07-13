"""
Модуль для управления автозаданиями системы Sova Monitoring
"""

from .routes import scheduler_bp

# Экспортируем blueprint напрямую
scheduler = scheduler_bp 