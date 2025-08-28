from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_socketio import SocketIO
from flask_login import LoginManager
from config import Config
import os

# Настройка логирования
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# SocketIO for realtime features
socketio = SocketIO(cors_allowed_origins="*", logger=True, engineio_logger=True, async_mode="threading")

# Инициализация расширений
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

def create_app(config_class=Config):
    app = Flask(__name__, template_folder='templates')
    app.config.from_object(config_class)

    # Инициализация расширений
    db.init_app(app)
    socketio.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # User loader для Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        return User.query.get(int(user_id))

    # Регистрация blueprint'ов
    from app.routes.auth import auth_bp
    from app.routes.admin import admin_bp
    from app.routes.partner import partner_bp
    from app.routes.manager import manager_bp
    from app.routes.supervisor import supervisor_bp
    from app.routes.api import api_bp
    from app.routes.devices import devices_bp
    from app.routes.payments import payments_bp
    from app.routes.reports import reports_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.client import client_bp
    from app.routes.partner_statistics import partner_statistics_bp
    from app.routes.user import user_bp
    from app.keys_management import keys_management
    from app.key_access import key_access_bp
    from app.scheduler import scheduler

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(partner_bp)
    app.register_blueprint(manager_bp)
    app.register_blueprint(supervisor_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(payments_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(client_bp)
    app.register_blueprint(partner_statistics_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(keys_management)
    app.register_blueprint(key_access_bp)
    app.register_blueprint(scheduler)

    # Импорт моделей для корректной работы миграций
    from app.models import User, Tariff, Payment, PartnerManagerAssociation, ManagerSupervisorAssociation, Earning, UserKey, UserOperation
    
    # WebSocket namespaces
    from . import ws_helpdesk
    from . import ws_helpdesk_mobile

    return app 