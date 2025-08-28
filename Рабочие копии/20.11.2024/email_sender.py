import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ssl

def send_email(to, subject, message):
    from_email = 'code@38-kvadratov.ru'
    password = 'hV1oI0sJ3w'
    server = 'mail.38-kvadratov.ru'
    port = 465

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(message))

    with smtplib.SMTP_SSL(server, port, context=context) as smtp_server:
        smtp_server.login(from_email, password)
        smtp_server.send_message(msg)
