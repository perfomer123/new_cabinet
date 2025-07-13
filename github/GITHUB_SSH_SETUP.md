# Настройка SSH ключа для GitHub (sova-cabinet)

## Шаг 1: Получить публичный ключ
Ваш публичный SSH ключ:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJZ7SXs5S4tHm2VvZ2jfBFbzg2sSlsvtdAfK3ZGNEbk rskyblue@yandex.ru
```

## Шаг 2: Добавить ключ в GitHub
1. Перейдите на https://github.com
2. Войдите в аккаунт `rskyblue@yandex.ru`
3. Перейдите в Settings → SSH and GPG keys
4. Нажмите "New SSH key"
5. Вставьте ключ выше в поле "Key"
6. Дайте название (например, "VDS Server")
7. Нажмите "Add SSH key"

## Шаг 3: Проверить подключение
После добавления ключа выполните:
```bash
ssh -T git@github.com
```

Должно появиться: "Hi rskyblue! You've successfully authenticated..."

## Шаг 4: Отправить код
После успешной настройки SSH выполните:
```bash
git push -u origin master
```

## Альтернативный способ (HTTPS)
Если SSH не работает, можно использовать HTTPS:
```bash
git remote set-url origin https://github.com/rskyblue/sova-cabinet.git
git push -u origin master
``` 