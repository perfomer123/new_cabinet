"""
Маршруты для управления автозаданиями
"""
from __future__ import annotations

import logging
from flask import Blueprint, jsonify, render_template, request, flash, redirect, url_for
from app.utils.decorators import auth_required, role_required
from app.utils.serializer import _to_serializable
from .tasks import SchedulerManager

logger = logging.getLogger(__name__)

scheduler_bp = Blueprint("scheduler", __name__, url_prefix="/scheduler")
scheduler_manager = SchedulerManager()

@scheduler_bp.route("/")
@auth_required
@role_required("admin")
def index():
    jobs = scheduler_manager.get_all_jobs()
    return render_template("scheduler/index.html", jobs=jobs)

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

@scheduler_bp.route("/config/<job_id>")
@auth_required
@role_required("admin")
def get_job_config(job_id: str):
    """
    Возвращает сериализуемую конфигурацию автозадания.
    Все несериализуемые атрибуты преобразуются функцией _to_serializable.
    """
    from flask import current_app
    try:
        current_app.logger.info("GET /config/%s", job_id)
        raw_cfg = scheduler_manager.get_job_config(job_id)
        if not raw_cfg:
            return jsonify({"success": False, "error": "Job not found"}), 404
        cleaned = _to_serializable(raw_cfg)
        current_app.logger.debug("Job %s, cleaned config: %s", job_id, cleaned)
        return jsonify({"success": True, "job": cleaned})
    except Exception as exc:
        current_app.logger.exception("config %s failed", job_id)
        return (
            jsonify({"success": False, "error": f"{type(exc).__name__}: {exc}"}),
            500,
        )

@scheduler_bp.route("/config/<job_id>", methods=["POST"])
@auth_required
@role_required("admin")
def update_job_config(job_id: str):
    """
    Обновляет конфигурацию автозадания и возвращает сериализованный результат.
    """
    try:
        data = request.get_json()
        if not scheduler_manager.update_job_config(job_id, data):
            return jsonify({"success": False, "error": "Ошибка обновления"}), 400
        updated_raw = scheduler_manager.get_job_config(job_id)
        return jsonify({"success": True, "job": _to_serializable(updated_raw)})
    except Exception as exc:
        logger.exception("update %s failed", job_id)
        return (
            jsonify({"success": False, "error": f"{type(exc).__name__}: {exc}"}),
            500,
        ) 