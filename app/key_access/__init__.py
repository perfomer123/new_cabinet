from flask import Blueprint

key_access_bp = Blueprint('key_access', __name__)

from . import routes 