from flask import Flask, request, render_template, redirect, url_for, jsonify
import bcrypt
import json
import logging
import subprocess
import os

app = Flask(__name__, template_folder='../templates', static_folder='../static')

def load_users():
    users_file_path = os.path.join(os.path.dirname(__file__), '../users/users.txt')
    print(f"Loading users from: {users_file_path}")  # Línea de depuración
    try:
        with open(users_file_path, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError:
        print("JSONDecodeError: El archivo está vacío o no contiene un JSON válido.")  # Línea de depuración
        return {}
    except FileNotFoundError:
        print("FileNotFoundError: No se encontró el archivo users.txt.")  # Línea de depuración
        return {}

def save_users(users):
    users_file_path = os.path.join(os.path.dirname(__file__), '../users/users.txt')
    print(f"Saving users to: {users_file_path}")  # Línea de depuración
    try:
        with open(users_file_path, 'w') as file:
            json.dump(users, file)
        print("Users saved successfully.")  # Línea de depuración
    except Exception as e:
        print(f"Error saving users: {e}")  # Línea de depuración

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode("utf-8")

        users = load_users()

        if username in users:
            return "Usuario ya registrado", 400

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode("utf-8")
        users[username] = hashed_password
        save_users(users)

        logging.info(f"Nuevo usuario registrado: {username} con hash: {hashed_password}")
        return render_template("register.html", username=username, hashed_password=hashed_password)
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode("utf-8")

        users = load_users()

        if username in users:
            stored_hash = users[username].encode("utf-8")
            password_is_correct = bcrypt.checkpw(password, stored_hash)
            
            logging.info(f"Intento de login para usuario: {username}")
            
            if password_is_correct:
                logging.info(f"Inicio de sesión exitoso para el usuario: {username}")
                return render_template("login.html", username=username, stored_hash=stored_hash.decode("utf-8"), login_success=True)
            else:
                logging.warning(f"Fallo en el inicio de sesión para el usuario: {username}")
                return render_template("login.html", username=username, stored_hash=stored_hash.decode("utf-8"), login_success=False)
        else:
            logging.warning(f"Usuario no encontrado: {username}")
            return render_template("login.html", username=username, stored_hash=None, login_success=False)
    return render_template("login.html")

@app.route("/audit_panel")
def audit_panel():
    return render_template("audit_panel.html")

@app.route("/scan_wifi")
def scan_wifi():
    result = subprocess.run(['python', os.path.join(os.path.dirname(__file__), 'wifi_scanner.py')], capture_output=True, text=True)
    networks = result.stdout.split('\n')
    formatted_result = "<br>".join(networks)
    return f"<pre>{formatted_result}</pre>"

@app.route("/list_interfaces")
def list_interfaces():
    if os.name == 'nt':  # Windows
        result = subprocess.run(['netsh', 'interface', 'show', 'interface'], capture_output=True, text=True)
    else:  # Linux
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
    interfaces = result.stdout.split('\n')
    return jsonify(interfaces)

@app.route("/start_monitor_mode", methods=["POST"])
def start_monitor_mode():
    interface = request.form.get("interface")
    if not interface:
        return "No se seleccionó ninguna interfaz", 400
    if os.name == 'nt':  # Windows
        return "Modo monitor no es compatible en Windows"
    else:  # Linux
        result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], capture_output=True, text=True)
        return f"<pre>{result.stdout}</pre>"

@app.route("/stop_monitor_mode", methods=["POST"])
def stop_monitor_mode():
    interface = request.form.get("interface")
    if not interface:
        return "No se seleccionó ninguna interfaz", 400
    if os.name == 'nt':  # Windows
        return "Modo monitor no es compatible en Windows"
    else:  # Linux
        result = subprocess.run(['sudo', 'airmon-ng', 'stop', interface], capture_output=True, text=True)
        return f"<pre>{result.stdout}</pre>"

@app.route("/reset")
def reset():
    interface = 'Wi-Fi'  # Cambia esto al nombre de tu interfaz de red en Windows
    subprocess.run(['netsh', 'interface', 'set', 'interface', interface, 'admin=disable'])
    subprocess.run(['netsh', 'interface', 'set', 'interface', interface, 'admin=enable'])
    return "Interfaz de red reiniciada"

@app.route("/deauth", methods=["POST"])
def deauth():
    bssid = request.form.get("bssid")
    client = request.form.get("client")
    if not bssid:
        return "No se proporcionó BSSID", 400
    if os.name == 'nt':  # Windows
        return "Ataque de desautenticación no es compatible en Windows"
    else:  # Linux
        command = ['sudo', 'aireplay-ng', '--deauth', '0', '-a', bssid]
        if client:
            command.extend(['-c', client])
        result = subprocess.run(command, capture_output=True, text=True)
        return f"<pre>{result.stdout}</pre>"

@app.route("/create_fake_ap", methods=["POST"])
def create_fake_ap():
    ssid = request.form.get("ssid")
    channel = request.form.get("channel")
    if not ssid or not channel:
        return "SSID o canal no proporcionado", 400
    if os.name == 'nt':  # Windows
        return "Creación de AP falso no es compatible en Windows"
    else:  # Linux
        result = subprocess.run(['sudo', 'airbase-ng', '-e', ssid, '-c', channel, 'wlan0mon'], capture_output=True, text=True)
        return f"<pre>{result.stdout}</pre>"

@app.route("/capture_handshake", methods=["POST"])
def capture_handshake():
    bssid = request.form.get("bssid")
    channel = request.form.get("channel")
    if not bssid or not channel:
        return "BSSID o canal no proporcionado", 400
    if os.name == 'nt':  # Windows
        return "Captura de handshakes no es compatible en Windows"
    else:  # Linux
        result = subprocess.run(['sudo', 'airodump-ng', '--bssid', bssid, '--channel', channel, '--write', 'handshake', 'wlan0mon'], capture_output=True, text=True)
        return f"<pre>{result.stdout}</pre>"

if __name__ == "__main__":
    log_path = os.path.join(os.path.dirname(__file__), '../logs/hashing_logs.log')
    logging.basicConfig(filename=log_path, level=logging.INFO)
    app.run(debug=True)