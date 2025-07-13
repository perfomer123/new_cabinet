from flask import Blueprint, render_template, g
from app.utils.decorators import auth_required, role_required
from app.services.partner_service import get_partner_data, calculate_days_left

partner_bp = Blueprint('partner', __name__)

@partner_bp.route('/partner')
@auth_required
@role_required('partner')
def dashboard():
    partner_id = g.user.id
    
    # Получаем все данные партнера
    data = get_partner_data(partner_id)
    
    return render_template('partner/dashboard.html', 
                         data=data,
                         calculate_days_left=calculate_days_left) 