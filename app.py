import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from flask_mysqldb import MySQL
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import logging

load_dotenv()

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
CORS(app)
api = Api(app)

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
jwt = JWTManager(app)

SWAGGER_URL = '/api/docs'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(SWAGGER_URL, API_URL, config={'app_name': "Flask MySQL API"})
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

class UserRegister(Resource):
    def post(self):
        try:
            data = request.get_json()
            username = data['username']
            email = data['email']
            password = generate_password_hash(data['password'])

            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO users(username, email, password) VALUES (%s, %s, %s)", (username, email, password))
            mysql.connection.commit()
            cursor.close()

            return jsonify({"message": "User registered successfully!"})
        except Exception as e:
            logging.error(f"Error registering user: {e}")
            return jsonify({"message": "Error registering user"}), 500

class UserLogin(Resource):
    def post(self):
        try:
            data = request.get_json()
            username = data['username']
            password = data['password']

            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            cursor.close()

            if user and check_password_hash(user[3], password):
                access_token = create_access_token(identity={'username': user[1]})
                return jsonify({"access_token": access_token})
            else:
                return jsonify({"message": "Invalid credentials!"}), 401
        except Exception as e:
            logging.error(f"Error logging in: {e}")
            return jsonify({"message": "Internal server error"}), 500

class Protected(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return jsonify(logged_in_as=current_user), 200

api.add_resource(UserRegister, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(Protected, '/protected')

if __name__ == '__main__':
    app.run(debug=True, port=int(os.environ.get('PORT', 5000)))
