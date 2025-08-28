from app import create_app, db
from app.models.support_ticket import SupportTicket

app = create_app()
with app.app_context():
    SupportTicket.__table__.create(db.engine, checkfirst=True)
    print('SupportTicket table ensured')
