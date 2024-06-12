from flask import Blueprint
from flask_restful import Api
from .auth import UserRegister, UserLogin, Protected

api_bp = Blueprint('api', __name__)
api = Api(api_bp)

api.add_resource(UserRegister, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(Protected, '/protected')
