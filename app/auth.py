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
            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
            existing_user = cursor.fetchone()
            if existing_user:
                cursor.close()
                return jsonify({"message": "Usuário já registrado!"}), 400

            cursor.execute("INSERT INTO users(username, email, password) VALUES (%s, %s, %s)", (username, email, password))
            mysql.connection.commit()
            cursor.close()

            return jsonify({"message": "Registrado com sucesso!"})
        except Exception as e:
            logging.error(f"Erro ao registrar usuário: {e}")
            return jsonify({"message": "Erro ao registrar usuário"}), 500

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
                return jsonify({"message": "Login realizado com sucesso!", "access_token": access_token})
            else:
                return jsonify({"message": "Usuário ou senha incorretos!"}), 401
        except Exception as e:
            logging.error(f"Erro ao fazer login: {e}")
            return jsonify({"message": "Erro interno do servidor"}), 500

class Protected(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return jsonify(logged_in_as=current_user), 200
