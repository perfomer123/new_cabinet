#!/bin/bash

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Sova Monitoring - Quick Commit ===${NC}"
echo ""

# Проверить статус Git
if [ ! -d ".git" ]; then
    echo -e "${RED}Ошибка: Это не Git репозиторий${NC}"
    exit 1
fi

# Показать статус
echo -e "${YELLOW}Статус Git:${NC}"
git status --short
echo ""

# Проверить есть ли изменения
if [ -z "$(git status --porcelain)" ]; then
    echo -e "${GREEN}Нет изменений для коммита${NC}"
    exit 0
fi

# Запросить описание коммита
echo -e "${YELLOW}Введите описание коммита:${NC}"
read -r message

# Проверить что сообщение не пустое
if [ -z "$message" ]; then
    echo -e "${RED}Ошибка: Описание коммита не может быть пустым${NC}"
    exit 1
fi

# Добавить все файлы
echo -e "${BLUE}Добавляю файлы...${NC}"
git add .

# Создать коммит
echo -e "${BLUE}Создаю коммит...${NC}"
if git commit -m "$message"; then
    echo -e "${GREEN}✅ Коммит создан успешно!${NC}"
    
    # Спросить про отправку на GitHub
    echo -e "${YELLOW}Отправить изменения на GitHub? (y/n):${NC}"
    read -r push_response
    
    if [[ $push_response =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}Отправляю на GitHub...${NC}"
        if git push; then
            echo -e "${GREEN}✅ Изменения отправлены на GitHub!${NC}"
        else
            echo -e "${RED}❌ Ошибка при отправке на GitHub${NC}"
        fi
    else
        echo -e "${YELLOW}Изменения сохранены локально${NC}"
    fi
else
    echo -e "${RED}❌ Ошибка при создании коммита${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=== Готово! ===${NC}" 