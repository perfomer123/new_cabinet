# sova-cabinet - Система управления майнинг-устройствами

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](VERSION)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-2.0+-red.svg)](https://flask.palletsprojects.com)

## Описание

Веб-приложение для мониторинга и управления майнинг-устройствами с поддержкой различных ролей пользователей (админ, партнёр, менеджер, супервайзер).

**Основные возможности:**
- 🚀 **Система автозаданий** с планировщиком APScheduler
- 📊 **Персонализированные отчеты** с отправкой в Telegram
- 🔑 **Управление ключами** с синхронизацией
- 👥 **Многоуровневая система ролей**
- 🔒 **Безопасность** и авторизация
- 📱 **Веб-интерфейс** для управления

## Быстрый старт

### Установка

```bash
# Клонирование репозитория
git clone https://github.com/perfomer123/sova-cabinet.git
cd sova-cabinet

# Установка зависимостей
pip install -r requirements.txt

# Настройка базы данных
python create_db.py

# Запуск приложения
python3 cabinet.py
```

### Конфигурация

1. Скопируйте `.env.example` в `.env`
2. Настройте переменные окружения
3. Запустите миграции: `python migrate.py`

## Документация

- 📋 [CHANGELOG](CHANGELOG.md) - История изменений
- 🔧 [Настройка](SETUP.md) - Подробная инструкция по установке
- 📚 [GitHub документация](github/) - Работа с Git и GitHub
- 🔑 [Управление ключами](app/keys_management/README.md) - Документация модуля

## Структура проекта

```
sova-cabinet/
├── app/                    # Основное приложение
│   ├── models/            # Модели данных
│   ├── routes/            # Маршруты API
│   ├── services/          # Бизнес-логика
│   ├── scheduler/         # Планировщик задач
│   ├── templates/         # HTML шаблоны
│   └── utils/             # Утилиты
├── migrations/            # Миграции БД
├── static/               # Статические файлы
├── github/               # Документация GitHub
├── cabinet.py            # Точка входа
├── config.py             # Конфигурация
├── requirements.txt      # Зависимости
└── README.md            # Документация
```

## API

### Автозадания

- `GET /scheduler/` - Список заданий
- `GET /scheduler/status` - Статус планировщика
- `GET /scheduler/config/{job_id}` - Конфигурация задания
- `POST /scheduler/config/{job_id}` - Обновление конфигурации

### Пользователи

- `GET /admin/users` - Список пользователей (админ)
- `POST /admin/users` - Создание пользователя
- `GET /dashboard` - Панель управления

## Роли пользователей

| Роль | Доступ |
|------|--------|
| **Админ** | Полный доступ ко всем функциям |
| **Партнёр** | Управление своими устройствами и статистика |
| **Менеджер** | Управление назначенными устройствами |
| **Супервайзер** | Мониторинг и диагностика |
| **Клиент** | Просмотр своих устройств |

## Автозадания

### Доступные задания

1. **update_key_status** - Обновление статуса ключей (интервал)
2. **sync_keys** - Синхронизация ключей (интервал)
3. **notify_user_about_key_status** - Уведомления о подписках (cron)
4. **calculate_metrics_and_send** - Ежедневные отчеты (cron)

### Настройка

- **Интервальные задания**: минуты, часы
- **Cron-задания**: день, час, минута
- **Автозапуск**: включение при старте приложения
- **Персонализация**: телефоны, приветствия, данные

## Безопасность

- 🔐 Аутентификация через сессии
- 🛡️ Защита от CSRF атак
- ✅ Валидация всех входных данных
- 📝 Подробное логирование

## Логирование

Логи сохраняются в файлы:
- `logs/app.log` - Основные логи приложения
- `logs/scheduler.log` - Логи планировщика
- `logs/errors.log` - Логи ошибок

## Разработка

### Требования

- Python 3.8+
- Flask 2.0+
- SQLAlchemy
- APScheduler

### Запуск в режиме разработки

```bash
export FLASK_ENV=development
python3 cabinet.py
```

## Поддержка

- 📧 Email: support@sova-cabinet.com
- 🐛 Issues: [GitHub Issues](https://github.com/perfomer123/sova-cabinet/issues)
- 📖 Документация: [Wiki](https://github.com/perfomer123/sova-cabinet/wiki)

## Лицензия

MIT License - см. файл [LICENSE](LICENSE) для подробностей.

---

**Версия**: 1.0.0  
**Дата**: 13.07.2025  
**Автор**: Команда Sova Cabinet 