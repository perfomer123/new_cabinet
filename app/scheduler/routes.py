"""
Маршруты для управления автозаданиями
"""

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, g
from functools import wraps
from ..utils.decorators import auth_required, role_required
from app.utils.serializer import _to_serializable
from .tasks import SchedulerManager
import logging

# Настройка логирования
logger = logging.getLogger(__name__)

scheduler_bp = Blueprint('scheduler', __name__, url_prefix='/scheduler')

# Инициализируем менеджер планировщика
scheduler_manager = SchedulerManager()

@scheduler_bp.route('/')
@auth_required
@role_required('admin')
def index():
    """Главная страница управления автозаданиями"""
    jobs = scheduler_manager.get_all_jobs()
    return render_template('scheduler/index.html', jobs=jobs)

@scheduler_bp.route('/start/<job_id>', methods=['POST'])
@auth_required
@role_required('admin')
def start_job(job_id):
    """Запуск автозадания"""
    try:
        success = scheduler_manager.start_job(job_id)
        if success:
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({'success': True, 'message': f'Автозадание "{job_id}" успешно запущено'})
            else:
                flash(f'Автозадание "{job_id}" успешно запущено', 'success')
        else:
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({'success': False, 'error': f'Ошибка запуска автозадания "{job_id}"'})
            else:
                flash(f'Ошибка запуска автозадания "{job_id}"', 'error')
    except Exception as e:
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': False, 'error': str(e)})
        else:
            flash(f'Ошибка: {str(e)}', 'error')
    
    return redirect(url_for('scheduler.index'))

@scheduler_bp.route('/stop/<job_id>', methods=['POST'])
@auth_required
@role_required('admin')
def stop_job(job_id):
    """Остановка автозадания"""
    try:
        success = scheduler_manager.stop_job(job_id)
        if success:
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({'success': True, 'message': f'Автозадание "{job_id}" остановлено'})
            else:
                flash(f'Автозадание "{job_id}" остановлено', 'success')
        else:
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({'success': False, 'error': f'Ошибка остановки автозадания "{job_id}"'})
            else:
                flash(f'Ошибка остановки автозадания "{job_id}"', 'error')
    except Exception as e:
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': False, 'error': str(e)})
        else:
            flash(f'Ошибка: {str(e)}', 'error')
    
    return redirect(url_for('scheduler.index'))

@scheduler_bp.route('/run/<job_id>', methods=['POST'])
@auth_required
@role_required('admin')
def run_job_now(job_id):
    """Запуск автозадания немедленно"""
    try:
        success = scheduler_manager.run_job_now(job_id)
        if success:
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({'success': True, 'message': f'Автозадание "{job_id}" выполнено'})
            else:
                flash(f'Автозадание "{job_id}" выполнено', 'success')
        else:
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({'success': False, 'error': f'Ошибка выполнения автозадания "{job_id}"'})
            else:
                flash(f'Ошибка выполнения автозадания "{job_id}"', 'error')
    except Exception as e:
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': False, 'error': str(e)})
        else:
            flash(f'Ошибка: {str(e)}', 'error')
    
    return redirect(url_for('scheduler.index'))

@scheduler_bp.route('/status')
@auth_required
@role_required('admin')
def get_status():
    """Получение статуса всех автозаданий"""
    try:
        status = scheduler_manager.get_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@scheduler_bp.route('/logs/<job_id>')
@auth_required
@role_required('admin')
def get_logs(job_id):
    """Получение логов автозадания"""
    try:
        logs = scheduler_manager.get_job_logs(job_id)
        return jsonify({'logs': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@scheduler_bp.route('/config/<job_id>')
@auth_required
@role_required('admin')
def get_job_config(job_id):
    """Получение конфигурации автозадания"""
    try:
        logger.info(f"Запрос конфигурации для задания: {job_id}")
        config = scheduler_manager.get_job_config(job_id)
        if config:
            # Сериализуем конфигурацию для безопасной передачи через JSON
            serialized_config = _to_serializable(config)
            logger.info(f"Конфигурация найдена для {job_id}: {serialized_config}")
            return jsonify({'success': True, 'job': serialized_config})
        else:
            logger.error(f"Конфигурация не найдена для задания: {job_id}")
            return jsonify({'success': False, 'error': 'Автозадание не найдено'})
    except Exception as e:
        logger.error(f"Ошибка получения конфигурации для {job_id}: {e}")
        return jsonify({'success': False, 'error': str(e)})

@scheduler_bp.route('/config/<job_id>', methods=['POST'])
@auth_required
@role_required('admin')
def update_job_config(job_id):
    """Обновление конфигурации автозадания"""
    try:
        data = request.get_json()
        success = scheduler_manager.update_job_config(job_id, data)
        if success:
            updated_config = scheduler_manager.get_job_config(job_id)
            return jsonify({'success': True, 'job': updated_config})
        else:
            return jsonify({'success': False, 'error': 'Ошибка обновления конфигурации'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}) 