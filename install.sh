#!/bin/bash

echo "🚀 Установка Сова Мониторинг..."

# Проверяем наличие Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 не найден. Установите Python 3.8+"
    exit 1
fi

# Проверяем версию Python
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Требуется Python 3.8+, установлена версия $python_version"
    exit 1
fi

echo "✅ Python $python_version найден"

# Создаем виртуальное окружение
if [ ! -d "venv" ]; then
    echo "📦 Создание виртуального окружения..."
    python3 -m venv venv
fi

# Активируем виртуальное окружение
echo "🔧 Активация виртуального окружения..."
source venv/bin/activate

# Обновляем pip
echo "⬆️ Обновление pip..."
pip install --upgrade pip

# Устанавливаем зависимости
echo "📚 Установка зависимостей..."
pip install -r requirements.txt

# Создаем необходимые папки
echo "📁 Создание папок..."
mkdir -p instance
mkdir -p logs
mkdir -p static

# Запускаем миграции
echo "🗄️ Инициализация базы данных..."
python migrate.py

echo "✅ Установка завершена!"
echo ""
echo "Для запуска приложения выполните:"
echo "source venv/bin/activate"
echo "python main.py"
echo ""
echo "Приложение будет доступно по адресу: http://localhost:5001" 