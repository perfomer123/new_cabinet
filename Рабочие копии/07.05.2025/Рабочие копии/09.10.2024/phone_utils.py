import requests
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Константы для доступа к API SMSC
SMSC_API_URL = "https://smsc.ru/sys/send.php"
SMSC_LOGIN = "rskyblue"  # Ваш логин от SMSC
SMSC_PASSWORD = "338W4dfi"  # Ваш пароль от SMSC

def send_sms(phone_number, message):
    """
    Функция для отправки SMS через сервис SMSC.

    :param phone_number: Номер телефона получателя в формате +79999999999
    :param message: Текст сообщения для отправки
    :return: Ответ от сервера SMSC
    """
    payload = {
        'login': SMSC_LOGIN,
        'psw': SMSC_PASSWORD,
        'phones': phone_number,
        'mes': message,
        'charset': 'utf-8',  # Для поддержки русского языка
        'fmt': 3,  # Формат ответа (3 - JSON)
    }

    try:
        logger.info(f"Sending SMS to {phone_number} with message: {message}")
        response = requests.get(SMSC_API_URL, params=payload)

        if response.status_code == 200:
            result = response.json()
            logger.info(f"Ответ от SMSC: {result}")
            if 'error' in result:
                logger.error(f"Ошибка при отправке SMS: {result['error']}")
                return False
            logger.info(f"SMS successfully sent to {phone_number}")
            return True
        else:
            logger.error(f"Ошибка HTTP: {response.status_code} при отправке SMS на номер {phone_number}")
            return False

    except Exception as e:
        logger.error(f"Исключение при отправке SMS на номер {phone_number}: {e}")
        return False
