from flask import Blueprint

keys_management = Blueprint('keys_management', __name__)
 
from . import routes 