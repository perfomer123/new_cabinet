from app import db
from app.models import UserKey, User, Tariff
from sqlalchemy import and_

def get_user_keys(page=1, per_page=10, start_date=None):
    query = db.session.query(
        UserKey.key,
        UserKey.start_date,
        UserKey.end_date,
        UserKey.status,
        User.username,
        Tariff.name.label('tariff_name')
    ).join(User, UserKey.user_id == User.id).outerjoin(Tariff, User.tariff_id == Tariff.id)
    
    if start_date:
        query = query.filter(UserKey.start_date >= start_date)
    
    total = query.count()
    keys = query.offset((page - 1) * per_page).limit(per_page).all()
    
    return keys, total 