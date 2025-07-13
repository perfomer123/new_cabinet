# 🚀 Установка и запуск Сова Мониторинг

## Быстрая установка

### 1. Автоматическая установка
```bash
./install.sh
```

### 2. Ручная установка

#### Требования
- Python 3.8+
- pip
- git

#### Шаги установки

1. **Клонирование репозитория**
```bash
git clone <repository-url>
cd cabinet
```

2. **Создание виртуального окружения**
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# или
venv\Scripts\activate  # Windows
```

3. **Установка зависимостей**
```bash
pip install -r requirements.txt
```

4. **Инициализация базы данных**
```bash
python migrate.py
```

5. **Запуск приложения**
```bash
python main.py
```

## 🔧 Конфигурация

### Основные настройки
Файл `config.py` содержит основные настройки:

```python
# База данных
DATABASE_PATH = 'instance/users.db'

# YooKassa (платежная система)
YOOKASSA_ACCOUNT_ID = 'your_account_id'
YOOKASSA_SECRET_KEY = 'your_secret_key'

# JWT токены
JWT_SECRET_KEY = 'your_secret_key'
```

### Переменные окружения
Можно использовать переменные окружения:

```bash
export FLASK_ENV=production
export DATABASE_URL=sqlite:///instance/prod.db
export YOOKASSA_ACCOUNT_ID=your_id
export YOOKASSA_SECRET_KEY=your_key
```

## 🏃‍♂️ Запуск

### Разработка
```bash
python main.py
```

### Продакшн
```bash
# Используя gunicorn
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5001 main:app

# Или используя uwsgi
pip install uwsgi
uwsgi --http 0.0.0.0:5001 --module main:app --processes 4
```

## 📁 Структура проекта

```
cabinet/
├── app/                    # Основное приложение
│   ├── models/            # Модели данных
│   ├── routes/            # Маршруты
│   ├── services/          # Бизнес-логика
│   ├── utils/             # Утилиты
│   └── __init__.py        # Инициализация
├── templates/             # HTML шаблоны
├── static/               # Статические файлы
├── instance/             # База данных
├── migrations/           # Миграции БД
├── config.py             # Конфигурация
├── main.py               # Точка входа
├── run.py                # Запуск с планировщиком
├── migrate.py            # Миграции
├── requirements.txt      # Зависимости
└── README.md            # Документация
```

## 🔐 Первоначальная настройка

### 1. Создание администратора
После первого запуска создайте администратора:

```python
from app import create_app, db
from app.models.user import User
from werkzeug.security import generate_password_hash

app = create_app()
with app.app_context():
    admin = User(
        username='admin',
        email='admin@example.com',
        password=generate_password_hash('password'),
        role='admin'
    )
    db.session.add(admin)
    db.session.commit()
```

### 2. Настройка тарифов
Создайте базовые тарифы:

```python
from app.models.tariff import Tariff

tariff = Tariff(
    name='Базовый',
    base_price=1000.0,
    partner_initial_payment=1000.0,
    manager_initial_payment=1000.0,
    supervisor_initial_payment=1000.0,
    partner_subscription_percentage=10.0,
    manager_subscription_percentage=5.0,
    supervisor_subscription_percentage=3.0
)
db.session.add(tariff)
db.session.commit()
```

## 🛠️ Обслуживание

### Резервное копирование
```bash
# База данных
cp instance/users.db backup/users_$(date +%Y%m%d_%H%M%S).db

# Логи
cp app.log backup/app_$(date +%Y%m%d_%H%M%S).log
```

### Обновление
```bash
git pull origin main
pip install -r requirements.txt
python migrate.py
```

### Мониторинг
```bash
# Логи приложения
tail -f app.log

# Логи системы
journalctl -u sovamonitoring -f
```

## 🐛 Устранение неполадок

### Проблемы с базой данных
```bash
# Пересоздание базы
rm instance/users.db
python migrate.py
```

### Проблемы с зависимостями
```bash
# Переустановка
pip uninstall -r requirements.txt
pip install -r requirements.txt
```

### Проблемы с правами
```bash
# Проверка прав
ls -la instance/
chmod 755 instance/
chmod 644 instance/*.db
```

## 📞 Поддержка

- **Email**: support@sovamonitoring.com
- **Telegram**: @sovamonitoring_support
- **Документация**: https://docs.sovamonitoring.com

## 📄 Лицензия

Проект распространяется под лицензией MIT.

---

**Версия**: 1.0.0  
**Дата**: 2024  
**Разработчик**: Сова Мониторинг 