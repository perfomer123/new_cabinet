from flask import Blueprint, render_template, g
from app.utils.decorators import auth_required, role_required
from app.services.manager_service import get_manager_data, calculate_days_left

manager_bp = Blueprint('manager', __name__)

@manager_bp.route('/manager')
@auth_required
@role_required('manager')
def dashboard():
    manager_id = g.user.id
    
    # Получаем все данные менеджера
    data = get_manager_data(manager_id)
    
    return render_template('manager/dashboard.html', 
                         data=data,
                         calculate_days_left=calculate_days_left) 