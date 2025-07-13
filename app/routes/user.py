from flask import Blueprint, render_template, g
from app.utils.decorators import auth_required, role_required
from app.services.user_service import get_user_data, calculate_days_left

user_bp = Blueprint('user', __name__)

@user_bp.route('/user')
@auth_required
@role_required('user')
def dashboard():
    user_id = g.user.id
    
    # Получаем все данные пользователя
    data = get_user_data(user_id)
    
    return render_template('user/dashboard.html', 
                         data=data,
                         calculate_days_left=calculate_days_left) 