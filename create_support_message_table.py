from app import create_app, db
from app.models.support_message import SupportMessage

app = create_app()
with app.app_context():
    SupportMessage.__table__.create(db.engine, checkfirst=True)
    print('SupportMessage table ensured')
