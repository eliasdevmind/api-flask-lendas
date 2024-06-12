from flask import request, jsonify
from flask_restful import Resource
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from . import mysql
import logging

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
