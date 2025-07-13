# Git Workflow для проекта Сова Мониторинг

## Настройка GitHub

### 1. Создание репозитория на GitHub

1. Перейдите на [GitHub](https://github.com)
2. Нажмите "New repository"
3. Название: `sova-monitoring`
4. Описание: "Система управления майнинг-устройствами"
5. Выберите "Private" (приватный)
6. НЕ ставьте галочки на README, .gitignore, license
7. Нажмите "Create repository"

### 2. Подключение локального репозитория к GitHub

```bash
# Добавить удалённый репозиторий
git remote add origin https://github.com/YOUR_USERNAME/sova-monitoring.git

# Отправить код на GitHub
git push -u origin master
```

## Ежедневная работа с Git

### Основные команды

```bash
# Проверить статус
git status

# Посмотреть изменения
git diff

# Добавить все изменения
git add .

# Добавить конкретный файл
git add app/key_access/routes.py

# Создать коммит
git commit -m "Описание изменений"

# Отправить изменения на GitHub
git push

# Получить изменения с GitHub
git pull
```

### Рекомендуемые сообщения коммитов

```bash
# Новые функции
git commit -m "feat: add user management module"

# Исправления багов
git commit -m "fix: resolve authentication issue"

# Улучшения
git commit -m "improve: enhance key access UI design"

# Документация
git commit -m "docs: update README with installation guide"

# Рефакторинг
git commit -m "refactor: restructure admin routes"
```

## Ветки (Branches)

### Создание новой ветки для функции

```bash
# Создать и переключиться на новую ветку
git checkout -b feature/new-module

# Внести изменения и закоммитить
git add .
git commit -m "feat: implement new module"

# Отправить ветку на GitHub
git push -u origin feature/new-module
```

### Слияние веток

```bash
# Переключиться на основную ветку
git checkout master

# Получить последние изменения
git pull origin master

# Слить ветку с функцией
git merge feature/new-module

# Удалить локальную ветку
git branch -d feature/new-module

# Удалить ветку на GitHub
git push origin --delete feature/new-module
```

## Работа в команде

### Получение изменений от других разработчиков

```bash
# Получить изменения
git pull origin master

# Если есть конфликты, разрешить их и закоммитить
git add .
git commit -m "resolve merge conflicts"
```

### Создание Pull Request

1. Создайте ветку для своей функции
2. Внесите изменения и закоммитьте
3. Отправьте ветку на GitHub
4. На GitHub создайте Pull Request
5. Дождитесь ревью и одобрения
6. Слейте изменения в master

## Полезные команды

### Просмотр истории

```bash
# Краткая история
git log --oneline

# Подробная история
git log

# История конкретного файла
git log --follow app/key_access/routes.py
```

### Отмена изменений

```bash
# Отменить изменения в рабочей директории
git checkout -- app/key_access/routes.py

# Отменить последний коммит (сохранить изменения)
git reset --soft HEAD~1

# Отменить последний коммит (удалить изменения)
git reset --hard HEAD~1
```

### Временное сохранение изменений

```bash
# Сохранить изменения во временной области
git stash

# Посмотреть сохранённые изменения
git stash list

# Применить последние сохранённые изменения
git stash pop

# Применить конкретные сохранённые изменения
git stash apply stash@{0}
```

## Автоматизация

### Создание скрипта для быстрого коммита

Создайте файл `commit.sh`:

```bash
#!/bin/bash
echo "Введите описание коммита:"
read message
git add .
git commit -m "$message"
git push
```

Сделайте его исполняемым:
```bash
chmod +x commit.sh
```

Использование:
```bash
./commit.sh
```

## Резервное копирование

### Создание тега для важных версий

```bash
# Создать тег
git tag -a v1.0.0 -m "Release version 1.0.0"

# Отправить тег на GitHub
git push origin v1.0.0
```

### Экспорт проекта

```bash
# Создать архив текущей версии
git archive --format=tar.gz --output=sova-monitoring-v1.0.0.tar.gz v1.0.0
```

## Безопасность

### Исключение конфиденциальных данных

Убедитесь, что в `.gitignore` исключены:
- Файлы с паролями
- Базы данных
- Логи
- Временные файлы
- Конфигурационные файлы с секретами

### Проверка перед коммитом

```bash
# Посмотреть что будет закоммичено
git diff --cached

# Проверить размер файлов
git status --porcelain | wc -l
```

## Рекомендации

1. **Частые коммиты**: Делайте коммиты часто, даже для небольших изменений
2. **Понятные сообщения**: Пишите понятные описания коммитов
3. **Тестирование**: Всегда тестируйте код перед коммитом
4. **Документация**: Обновляйте документацию при изменении API
5. **Ревью кода**: Используйте Pull Requests для ревью кода

---

**Дата создания**: 13.07.2025  
**Версия**: 1.0.0 