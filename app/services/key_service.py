from app import db
from app.models import UserKey

def add_keys(user_id, keys):
    for key in keys:
        if not UserKey.query.filter_by(key=key).first():
            user_key = UserKey(user_id=user_id, key=key)
            db.session.add(user_key)
    db.session.commit()

def detach_keys(user_id, keys):
    for key in keys:
        user_key = UserKey.query.filter_by(user_id=user_id, key=key).first()
        if user_key:
            db.session.delete(user_key)
    db.session.commit()

def is_key_attached(key):
    return UserKey.query.filter_by(key=key).first() is not None 