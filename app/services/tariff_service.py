from app import db
from app.models import Tariff

def get_tariff_by_id(tariff_id):
    return Tariff.query.get(tariff_id)

def get_all_tariffs():
    return Tariff.query.all()

def create_tariff(**kwargs):
    tariff = Tariff(**kwargs)
    db.session.add(tariff)
    db.session.commit()
    return tariff

def update_tariff(tariff_id, **kwargs):
    tariff = Tariff.query.get(tariff_id)
    for key, value in kwargs.items():
        setattr(tariff, key, value)
    db.session.commit()
    return tariff

def delete_tariff(tariff_id):
    tariff = Tariff.query.get(tariff_id)
    db.session.delete(tariff)
    db.session.commit() 