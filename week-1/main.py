from flask import Flask, request, jsonify, render_template, redirect, url_for
import string
import time

app = Flask(__name__)

# Database simulations
users_db = {
    "user1": {"login": "user1", "secret": "pass1"},
    "user2": {"login": "user2", "secret": "pass2"},
}
methods_db = {
    1: {
        "id": 1,
        "caption": "Vigenere Cipher",
        "json_params": {"key": "str"},
        "description": "Encrypts and decrypts text using the Vigenere cipher method."
    },
    2: {
        "id": 2,
        "caption": "Caesar Cipher",
        "json_params": {"shift": "int"},
        "description": "Encrypts and decrypts text using the Caesar cipher method."
    }
}
sessions_db = {}

alphabet = " ,.:(_)-0123456789АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

# Utility functions for encryption/decryption
def vigenere_cipher(text, key, decrypt=False):
    key = key.upper()
    key = ''.join([c for c in key if c in alphabet])
    if not key:
        return None

    transformed = []
    key_index = 0

    for char in text:
        if char in alphabet:
            char_index = alphabet.index(char)
            key_char = key[key_index % len(key)]
            key_char_index = alphabet.index(key_char)
            if decrypt:
                new_index = (char_index - key_char_index) % len(alphabet)
            else:
                new_index = (char_index + key_char_index) % len(alphabet)
            transformed.append(alphabet[new_index])
            key_index += 1
        else:
            transformed.append(char)

    return ''.join(transformed)

def caesar_cipher(text, shift, decrypt=False):
    shift = int(shift) % len(alphabet)
    if decrypt:
        shift = -shift

    transformed = []
    for char in text:
        if char in alphabet:
            char_index = alphabet.index(char)
            new_index = (char_index + shift) % len(alphabet)
            transformed.append(alphabet[new_index])
        else:
            transformed.append(char)

    return ''.join(transformed)

@app.route('/')
def index():
    return render_template('index.html', methods=methods_db.values())

@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.json
    login = data.get('login')
    secret = data.get('secret')
    if login and secret and 3 <= len(login) <= 30 and 3 <= len(secret) <= 30:
        if login not in users_db:
            users_db[login] = {'login': login, 'secret': secret}
            return jsonify({"message": "User added successfully"}), 201
        else:
            return jsonify({"message": "User already exists"}), 400
    else:
        return jsonify({"message": "Invalid login or secret length"}), 400

@app.route('/users', methods=['GET'])
def get_users():
    return jsonify([{"login": user["login"]} for user in users_db.values()])

@app.route('/methods', methods=['GET'])
def get_methods():
    return jsonify(list(methods_db.values()))

@app.route('/encrypt_decrypt', methods=['POST'])
def encrypt_decrypt():
    user_login = request.form.get('user_login')
    user_secret = request.form.get('user_secret')
    method_id = int(request.form.get('method_id'))
    text = request.form.get('text')
    action = request.form.get('action')
    params = {}

    if method_id == 1:
        params['key'] = request.form.get('key')
    elif method_id == 2:
        params['shift'] = int(request.form.get('shift'))

    if user_login in users_db and users_db[user_login]['secret'] == user_secret:
        method = methods_db.get(method_id)
        if not method:
            return jsonify({"message": "Invalid method ID"}), 400

        start_time = time.time()
        if method_id == 1:
            key = params.get('key')
            if not key:
                return jsonify({"message": "Missing key for Vigenere cipher"}), 400
            if action == "encrypt":
                result = vigenere_cipher(text, key, decrypt=False)
            elif action == "decrypt":
                result = vigenere_cipher(text, key, decrypt=True)
            else:
                return jsonify({"message": "Invalid action"}), 400
        elif method_id == 2:
            shift = params.get('shift')
            if shift is None:
                return jsonify({"message": "Missing shift for Caesar cipher"}), 400
            if action == "encrypt":
                result = caesar_cipher(text, shift, decrypt=False)
            elif action == "decrypt":
                result = caesar_cipher(text, shift, decrypt=True)
            else:
                return jsonify({"message": "Invalid action"}), 400
        else:
            return jsonify({"message": "Unknown method"}), 400

        end_time = time.time()
        session_id = len(sessions_db) + 1
        session = {
            "id": session_id,
            "user_id": user_login,
            "method_id": method_id,
            "data_in": text,
            "params": params,
            "data_out": result,
            "status": "completed",
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time)),
            "time_op": end_time - start_time
        }
        sessions_db[session_id] = session

        return render_template('result.html', session=session)
    else:
        return jsonify({"message": "Invalid user login or secret"}), 400

@app.route('/session/<int:session_id>', methods=['GET'])
def get_session(session_id):
    session = sessions_db.get(session_id)
    if session:
        return jsonify(session)
    else:
        return jsonify({"message": "Session not found"}), 404

@app.route('/delete_session/<int:session_id>', methods=['POST'])
def delete_session(session_id):
    global sessions_db

    user_secret = request.form.get('user_secret')

    session = sessions_db.get(session_id)
    if not session:
        return jsonify({"message": "Session not found"}), 404

    user_login = session['user_id']
    if user_login in users_db and users_db[user_login]['secret'] == user_secret:
        del sessions_db[session_id]
        return render_template('result.html', session=session, session_deleted=True)
    else:
        return render_template('result.html', session=session, password_incorrect=True)

if __name__ == '__main__':
    app.run(debug=True)