from app import db
from app.models import PartnerManagerAssociation, ManagerSupervisorAssociation

def add_partner_manager(partner_id, manager_id):
    assoc = PartnerManagerAssociation(partner_id=partner_id, manager_id=manager_id)
    db.session.add(assoc)
    db.session.commit()
    return assoc

def add_manager_supervisor(manager_id, supervisor_id):
    assoc = ManagerSupervisorAssociation(manager_id=manager_id, supervisor_id=supervisor_id)
    db.session.add(assoc)
    db.session.commit()
    return assoc

def get_managers_for_partner(partner_id):
    return ManagerSupervisorAssociation.query.filter_by(partner_id=partner_id).all()

def get_supervisors_for_manager(manager_id):
    return ManagerSupervisorAssociation.query.filter_by(manager_id=manager_id).all() 