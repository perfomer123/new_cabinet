from flask import Blueprint, render_template, g
from app.utils.decorators import auth_required, role_required
from app.services.supervisor_service import get_supervisor_data, calculate_days_left

supervisor_bp = Blueprint('supervisor', __name__)

@supervisor_bp.route('/supervisor')
@auth_required
@role_required('supervisor')
def dashboard():
    supervisor_id = g.user.id
    data = get_supervisor_data(supervisor_id)
    return render_template('supervisor/dashboard.html', data=data, calculate_days_left=calculate_days_left) 