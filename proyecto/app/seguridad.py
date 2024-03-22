from flask import Flask, request, jsonify, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from itsdangerous import URLSafeTimedSerializer
from werkzeug.exceptions import HTTPException
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import random

app = Flask(__name__)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.secret_key = 'super secret key'
app.config['SESSION_TYPE'] = 'filesystem'

# Base de datos simulada para almacenar usuarios y contraseñas
users = {
    "usuario1": bcrypt.generate_password_hash("contraseña1").decode('utf-8'),
    "usuario2": bcrypt.generate_password_hash("contraseña2").decode('utf-8'),
    "usuario3": bcrypt.generate_password_hash("password3").decode('utf-8')
}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

@app.route('/login', methods=['POST'])
def login():
    user = request.form.get('user')
    password = request.form.get('password')
    if user in users and bcrypt.check_password_hash(users[user], password):
        user_obj = User(user)
        login_user(user_obj)
        return jsonify({"message": "Usuario autenticado con exito"}), 200
    else:
        return jsonify({"message": "Error de autenticacion"}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Usuario deslogueado con exito"}), 200

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    data = request.form.get('data')
    if data is None:
        return jsonify({"error": "No se proporcionaron datos para encriptar"}), 400

    # Genera una clave aleatoria de 16 bytes
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)

    # Encripta los datos
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    # Devuelve los datos encriptados, la clave y el nonce en formato base64
    encrypted_data = b64encode(ciphertext).decode('utf-8')
    key = b64encode(key).decode('utf-8')
    nonce = b64encode(cipher.nonce).decode('utf-8')
    return jsonify({"encrypted_data": encrypted_data, "key": key, "nonce": nonce})

@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    encrypted_data = request.form.get('encrypted_data')
    key = request.form.get('key')
    nonce = request.form.get('nonce')
    if encrypted_data is None or key is None or nonce is None:
        return jsonify({"error": "No se proporcionaron datos para desencriptar, la clave o el nonce"}), 400

    try:
        # Crea un nuevo objeto de cifrado AES con la clave y el nonce proporcionados
        cipher = AES.new(b64decode(key), AES.MODE_EAX, nonce=b64decode(nonce))

        # Desencripta los datos
        decrypted_data = cipher.decrypt(b64decode(encrypted_data)).decode('utf-8')
        return jsonify({"decrypted_data": decrypted_data})
    except Exception as e:
        return jsonify({"error": "Desencriptación fallida: " + str(e)}), 400

@app.route('/test', methods=['POST'])
@login_required
def penetration_test():
    # Obtenemos los datos de la solicitud
    data = request.form.get('data')

    # Intentamos usar los datos en una consulta SQL
    try:
        # Aquí deberías ejecutar una consulta SQL real utilizando los datos
        # Por ahora, solo vamos a simularlo
        if "DROP TABLE" in data:
            raise Exception("Inyección SQL detectada")

        return jsonify({"message": "Prueba de penetración exitosa"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.errorhandler(HTTPException)
def handle_exception(e):
    # manejo de errores HTTP
    response = e.get_response()
    response.data = jsonify({"code": e.code, "name": e.name, "description": e.description})
    response.content_type = "application/json"
    return response

@app.errorhandler(Exception)
def handle_exception(e):
    # Obtén el mensaje de error original
    original_error = str(e)

    # Crea una respuesta JSON con el mensaje de error
    response = jsonify({"error": original_error})

    # Devuelve la respuesta con el código de estado 500 (Error interno del servidor)
    response.status_code = 500

    return response

@app.route('/', methods=['GET'])
def home():
    return "Funcionaaaaaa!"

if __name__ == '__main__':
    if app.debug:
        app.run(host='0.0.0.0', debug=True)
    else:
        app.run(host='0.0.0.0', debug=False, ssl_context='adhoc')