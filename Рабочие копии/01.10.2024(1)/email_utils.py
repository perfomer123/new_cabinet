import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ssl
import time
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def send_email(to, subject, message):
    from_email = 'noreply@sovamon.ru'
    password = 'ou9jmasdg8'
    server = 'mail.salebot.pro'
    port = 587

    # Создание защищенного контекста SSL
    context = ssl.create_default_context()

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(message))

    try:
        logger.info(f"Connecting to the SMTP server {server} on port {port}")
        start_time = time.time()

        with smtplib.SMTP(server, port) as smtp_server:
            smtp_server.starttls(context=context)  # Обеспечиваем защищенное соединение
            logger.info(f"Time taken for TLS handshake: {time.time() - start_time:.2f} seconds")

            login_start_time = time.time()
            smtp_server.login(from_email, password)
            logger.info(f"Time taken to login: {time.time() - login_start_time:.2f} seconds")

            send_start_time = time.time()
            smtp_server.send_message(msg)
            logger.info(f"Time taken to send email: {time.time() - send_start_time:.2f} seconds")

        logger.info(f"Email successfully sent to {to}")

    except Exception as e:
        logger.error(f"Error sending email to {to}: {e}")
