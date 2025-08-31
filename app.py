from flask import Flask, render_template, request, Response, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os, json, tempfile, subprocess
from cryptography.fernet import Fernet
import datetime
from ldap3 import Server, Connection, ALL, SIMPLE

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "supersecretkey")

# ---------------- SQLite Setup ----------------
DB_DIR = os.path.join(os.path.dirname(__file__), "instance")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "runs.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------------- Models ----------------
class Run(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    results = db.Column(db.JSON)

with app.app_context():
    db.create_all()

# ---------------- Predefined Accounts ----------------
PREDEFINED_FILE = "predefined_accounts.json"
if not os.path.isfile(PREDEFINED_FILE):
    open(PREDEFINED_FILE, "w").write("{}")
with open(PREDEFINED_FILE) as f:
    PREDEFINED_ACCOUNTS = json.load(f)

KEY_FILE = "fernet.key"
if not os.path.isfile(KEY_FILE):
    raise FileNotFoundError(f"Fernet key file '{KEY_FILE}' not found. Generate it first.")
with open(KEY_FILE, "r") as kf:
    ENCRYPTION_KEY = kf.read().strip()
cipher = Fernet(ENCRYPTION_KEY.encode())

def decrypt_password(enc_password):
    return cipher.decrypt(enc_password.encode()).decode()

# ---------------- Authentication ----------------
LDAP_SERVER = "ldap://amer.epiqcorp.com"
LDAP_DOMAIN = "amer.epiqcorp.com"

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        try:
            server = Server(LDAP_SERVER, get_info=ALL)
            conn = Connection(server, user=f"{username}@{LDAP_DOMAIN}", password=password, authentication=SIMPLE)
            if conn.bind():
                session['username'] = username
                return redirect(url_for("index"))
            else:
                error = "Invalid username or password"
        except Exception as e:
            error = str(e)
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

# ---------------- Main Deployment ----------------
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        account_key = request.form.get("predefined_account")
        use_predefined = account_key and account_key in PREDEFINED_ACCOUNTS

        if use_predefined:
            account = PREDEFINED_ACCOUNTS[account_key]
            username = account["username"]
            password = decrypt_password(account["password"])
            sudo_password = decrypt_password(account["sudo_password"])
            activation_key = account["activation_key"]
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            sudo_password = request.form.get("sudo_password", "").strip()
            activation_key = request.form.get("activation_key", "").strip()

        if not username or not password or not activation_key:
            return "Error: username, password, and activation key are required.", 400

        hosts = request.form.get("hosts", "").splitlines()
        groups = request.form.get("groups", "")
        mode = request.form.get("mode", "cloud")
        manager_host = request.form.get("manager_host", "")
        manager_port = request.form.get("manager_port", "8834")
        escalate_method = request.form.get("escalate_method", "sudo")
        remove_rapid7 = request.form.get("remove_rapid7", "false") == "true"

        # --- Ephemeral Ansible Inventory ---
        inventory_content = "[agents]\n" + "\n".join(hosts) + "\n\n"
        inventory_content += "[agents:vars]\n"
        inventory_content += f"ansible_user={username}\n"
        inventory_content += f"ansible_password={password}\n"
        inventory_content += f"ansible_become_password={sudo_password}\n"
        inventory_content += f"activation_key={activation_key}\n"
        inventory_content += f"groups={groups}\n"
        inventory_content += f"mode={mode}\n"
        inventory_content += f"manager_host={manager_host}\n"
        inventory_content += f"manager_port={manager_port}\n"
        inventory_content += f"escalate_method={escalate_method}\n"
        inventory_content += f"remove_rapid7={str(remove_rapid7).lower()}\n"

        tmp_inventory = tempfile.NamedTemporaryFile(delete=False)
        tmp_inventory.write(inventory_content.encode())
        tmp_inventory.close()

        results_dict = {}

        def stream_logs():
            cmd = ["ansible-playbook", "-i", tmp_inventory.name, "deploy_nessus_agent.yml"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            for line in iter(process.stdout.readline, ""):
                line = line.strip()
                yield f"data:{line}\n\n"

                # Attempt to parse JSON host result
                try:
                    host_result = json.loads(line)
                    results_dict[host_result['host']] = host_result
                except:
                    pass

            process.stdout.close()
            os.unlink(tmp_inventory.name)

            # Save results to DB
            if results_dict:
                run = Run(user=session['username'], results=results_dict)
                with app.app_context():
                    db.session.add(run)
                    db.session.commit()

        return Response(stream_logs(), mimetype='text/event-stream')

    return render_template("index.html", predefined_accounts=PREDEFINED_ACCOUNTS, session=session)

# ---------------- History Page ----------------
@app.route("/history")
@login_required
def history():
    runs = Run.query.order_by(Run.timestamp.desc()).all()
    return render_template("history.html", runs=runs, session=session)

# ---------------- Run Flask ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, debug=True)
