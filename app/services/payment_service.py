import yookassa
from datetime import datetime, timedelta
from app import db
from app.models import Payment
from app.models.user_key import UserKey

class PaymentService:
    @staticmethod
    def get_extension_days(duration):
        """Получение количества дней продления по длительности"""
        duration_map = {
            '1_month': 30,
            '3_months': 90,
            '6_months': 180,
            '1_year': 365
        }
        return duration_map.get(duration, 30)
    
    @staticmethod
    def get_amount(duration):
        """Получение суммы платежа по длительности"""
        amount_map = {
            '1_month': 1000,
            '3_months': 2700,
            '6_months': 4800,
            '1_year': 8400
        }
        return amount_map.get(duration, 1000)
    
    @staticmethod
    def calculate_new_end_date(current_end_date, extension_days):
        """Вычисление новой даты окончания подписки"""
        if not current_end_date:
            # Если нет текущей даты окончания, начинаем с сегодня
            new_end_date = datetime.now() + timedelta(days=extension_days)
        else:
            try:
                # Парсим текущую дату окончания
                if isinstance(current_end_date, str):
                    current_date = datetime.strptime(current_end_date, '%Y-%m-%d %H:%M:%S')
                else:
                    current_date = current_end_date
                
                # Добавляем дни продления
                new_end_date = current_date + timedelta(days=extension_days)
            except ValueError:
                # Если ошибка парсинга, начинаем с сегодня
                new_end_date = datetime.now() + timedelta(days=extension_days)
        
        return new_end_date.strftime('%Y-%m-%d %H:%M:%S')
    
    @staticmethod
    def create_payment(user_id, tariff_id, amount, extension_days, key, payment_id):
        """Создание записи о платеже"""
        payment = Payment(user_id=user_id, tariff_id=tariff_id, amount=amount, extension_days=extension_days, key=key, payment_id=payment_id, payment_date=datetime.utcnow(), processed=False)
        db.session.add(payment)
        db.session.commit()
        return payment
    
    @staticmethod
    def process_successful_payment(payment_id):
        """Обработка успешного платежа"""
        try:
            payment = Payment.query.filter_by(payment_id=payment_id).first()
            if not payment:
                return False, "Платеж не найден"
            
            if payment.processed:
                return False, "Платеж уже обработан"
            
            # Обновляем ключ пользователя
            user_key = UserKey.query.filter_by(key=payment.key).first()
            if user_key:
                # Вычисляем новую дату окончания
                new_end_date = PaymentService.calculate_new_end_date(
                    user_key.end_date, 
                    payment.extension_days
                )
                user_key.end_date = new_end_date
                user_key.status = 'active'
            
            # Отмечаем платеж как обработанный
            payment.processed = True
            db.session.commit()
            
            return True, "Платеж успешно обработан"
            
        except Exception as e:
            db.session.rollback()
            return False, f"Ошибка обработки платежа: {str(e)}"
    
    @staticmethod
    def create_yookassa_payment(amount, description, return_url):
        """Создание платежа в YooKassa"""
        try:
            payment = yookassa.Payment.create({
                "amount": {
                    "value": str(amount),
                    "currency": "RUB"
                },
                "confirmation": {
                    "type": "redirect",
                    "return_url": return_url
                },
                "capture": True,
                "description": description
            })
            return payment
        except Exception as e:
            print(f"Ошибка создания платежа в YooKassa: {e}")
            return None 

def create_payment(user_id, tariff_id, amount, extension_days, key, payment_id):
    payment = Payment(user_id=user_id, tariff_id=tariff_id, amount=amount, extension_days=extension_days, key=key, payment_id=payment_id, payment_date=datetime.utcnow(), processed=False)
    db.session.add(payment)
    db.session.commit()
    return payment

def get_payment_by_id(payment_id):
    return Payment.query.filter_by(payment_id=payment_id).first()

def mark_payment_processed(payment_id):
    payment = Payment.query.filter_by(payment_id=payment_id).first()
    if payment:
        payment.processed = True
        db.session.commit()
    return payment 