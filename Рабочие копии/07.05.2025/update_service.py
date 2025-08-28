# update_service.py

# Пример хранения последней версии в базе данных или в переменной
LATEST_VERSION = "1.1.4"

def is_update_required(current_version):
    """
    Проверяет, требуется ли обновление приложения.
    :param current_version: Текущая версия приложения, переданная клиентом.
    :return: True, если обновление требуется, False иначе.
    """
    
    # Логируем текущую версию клиента и последнюю версию сервера
    print(f"Client version: {current_version}")
    print(f"Latest version: {LATEST_VERSION}")
    
    # Сравниваем текущую версию с последней версией
    if current_version != LATEST_VERSION:
        print("Update required: True")  # Логируем, что обновление требуется
        return True
    else:
        print("Update required: False")  # Логируем, что обновление не требуется
        return False
