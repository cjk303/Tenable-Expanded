import os
import json
import tempfile
import subprocess
from flask import Flask, render_template, request, redirect, url_for, Response, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from ldap3 import Server, Connection, ALL
from models import db, Run
import json

# -------------------- Flask Setup --------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")

# Ensure instance folder exists
basedir = os.path.abspath(os.path.dirname(__file__))
instance_dir = os.path.join(basedir, "instance")
os.makedirs(instance_dir, exist_ok=True)

# Absolute path to SQLite DB
db_file = os.path.join(instance_dir, "runs.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_file}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
with app.app_context():
    db.create_all()

# -------------------- Login Manager --------------------
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class LDAPUser(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    return LDAPUser(user_id)

# -------------------- Predefined Accounts --------------------
PREDEFINED_FILE = "predefined_accounts.json"
if not os.path.isfile(PREDEFINED_FILE):
    open(PREDEFINED_FILE, "w").write("{}")

with open(PREDEFINED_FILE) as f:
    PREDEFINED_ACCOUNTS = json.load(f)

KEY_FILE = "fernet.key"
if not os.path.isfile(KEY_FILE):
    raise FileNotFoundError(f"Fernet key file '{KEY_FILE}' not found.")

with open(KEY_FILE, "r") as kf:
    ENCRYPTION_KEY = kf.read().strip()
cipher = Fernet(ENCRYPTION_KEY.encode())

def decrypt_password(enc_password):
    return cipher.decrypt(enc_password.encode()).decode()

# -------------------- Routes --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        server = Server("amer.epiqcorp.com", get_info=ALL)
        try:
            # SIMPLE bind using userPrincipalName
            conn = Connection(
                server,
                user=f"{username}@amer.epiqcorp.com",
                password=password,
                authentication="SIMPLE",
                auto_bind=True
            )

            # Any AD member allowed
            user = LDAPUser(username)
            login_user(user)
            return redirect(url_for("index"))

        except Exception:
            error = "Invalid username or password."

    return render_template("login.html", error=error)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/", methods=["GET","POST"])
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
        remove_rapid7 = request.form.get("remove_rapid7", "false")

        # Ephemeral Ansible Inventory
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
        inventory_content += f"remove_rapid7={remove_rapid7}\n"

        tmp_inventory = tempfile.NamedTemporaryFile(delete=False)
        tmp_inventory.write(inventory_content.encode())
        tmp_inventory.close()

        # Stream logs to browser using SSE
        def stream_logs():
            cmd = ["ansible-playbook", "-i", tmp_inventory.name, "deploy_nessus_agent.yml", "-v", "-o"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            results = {}
            logs = []

            for line in iter(process.stdout.readline, ''):
                logs.append(line)
                yield f"data:{line}\n\n"

                for host in hosts:
                    if host in line:
                        if host not in results:
                            results[host] = {"removed_rapid7": False, "installed_tenable": False, "status":"unknown", "details": ""}
                        if "rapid7" in line.lower():
                            results[host]["removed_rapid7"] = True
                        if "tenable" in line.lower():
                            results[host]["installed_tenable"] = True
                        if "FAILED" in line:
                            results[host]["status"] = "failed"
                            results[host]["details"] += line.strip() + " "
                        elif "SUCCESS" in line and results[host]["status"] != "failed":
                            results[host]["status"] = "success"

            process.stdout.close()
            os.unlink(tmp_inventory.name)

            # Save run to DB at the end
            run = Run(user=current_user.id, logs="".join(logs), results=results)
            db.session.add(run)
            db.session.commit()

        return Response(stream_logs(), mimetype='text/event-stream')

    return render_template("index.html", predefined_accounts=PREDEFINED_ACCOUNTS)

# -------------------- History & CSV --------------------
@app.route("/history")
@login_required
def history():
    runs = Run.query.order_by(Run.timestamp.desc()).all()
    return render_template("history.html", runs=runs)

@app.route("/history/<int:run_id>")
@login_required
def view_run(run_id):
    run = Run.query.get_or_404(run_id)
    return render_template("view_run.html", run=run)

@app.route("/history/<int:run_id>/csv")
@login_required
def export_run_csv(run_id):
    run = Run.query.get_or_404(run_id)
    output = [["Hostname", "Rapid7 Removed", "Tenable Installed", "Status"]]
    for host, data in run.results.items():
        output.append([
            host,
            "Yes" if data.get("removed_rapid7") else "No",
            "Yes" if data.get("installed_tenable") else "No",
            data.get("status", "")
        ])
    from io import StringIO
    si = StringIO()
    cw = csv.writer(si)
    cw.writerows(output)
    response = make_response(si.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=run_{run.id}_results.csv"
    response.headers["Content-Type"] = "text/csv"
    return response

# -------------------- Main --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, debug=True)
