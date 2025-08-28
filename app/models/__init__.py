# Models package

# Импорт всех моделей для корректной работы миграций
from .user import User
from .tariff import Tariff
from .payment import Payment
from .association import PartnerManagerAssociation, ManagerSupervisorAssociation
from .earning import Earning
from .user_key import UserKey
from .user_operation import UserOperation
from .support_ticket import SupportTicket
from .support_message import SupportMessage

__all__ = [
    'User',
    'Tariff', 
    'UserKey',
    'UserOperation',
    'PartnerManagerAssociation',
    'ManagerSupervisorAssociation',
    'Earning',
    'Payment'
] 