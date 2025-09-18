from flask import (
    Flask, render_template, request, Response,
    redirect, url_for, session, flash
)
from ldap3 import Server, Connection, SIMPLE, ALL
from functools import wraps
import os, json, tempfile, subprocess
from cryptography.fernet import Fernet

app = Flask(__name__)

# 🔑 Use a strong random secret key in production!
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super-secret-key")

# LDAP domain
LDAP_DOMAIN = "amer.epiqcorp.com"

# ------------------ LDAP AUTH ------------------ #
def authenticate_user(username, password):
    """
    Simple bind to amer.epiqcorp.com with username@amer.epiqcorp.com
    """
    user_principal = f"{username}@{LDAP_DOMAIN}"
    server = Server(LDAP_DOMAIN, get_info=ALL, port=636, use_ssl=True)  # use LDAPS
    try:
        conn = Connection(server, user=user_principal, password=password,
                          authentication=SIMPLE, auto_bind=True)
        conn.unbind()
        return True
    except Exception as e:
        app.logger.warning(f"LDAP auth failed for {user_principal}: {e}")
        return False

# ------------------ LOGIN REQUIRED DECORATOR ------------------ #
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ------------------ ROUTES ------------------ #
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if authenticate_user(username, password):
            session["username"] = f"{username}@{LDAP_DOMAIN}"
            flash("Login successful!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    # Load predefined accounts
    PREDEFINED_FILE = "predefined_accounts.json"
    if not os.path.isfile(PREDEFINED_FILE):
        open(PREDEFINED_FILE, "w").write("{}")

    with open(PREDEFINED_FILE) as f:
        PREDEFINED_ACCOUNTS = json.load(f)

    # Load Fernet key
    KEY_FILE = "fernet.key"
    if not os.path.isfile(KEY_FILE):
        raise FileNotFoundError(f"Fernet key file '{KEY_FILE}' not found. Generate it first.")

    with open(KEY_FILE, "r") as kf:
        ENCRYPTION_KEY = kf.read().strip()

    cipher = Fernet(ENCRYPTION_KEY.encode())

    def decrypt_password(enc_password):
        return cipher.decrypt(enc_password.encode()).decode()

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

        tmp_inventory = tempfile.NamedTemporaryFile(delete=False, mode="w")
        tmp_inventory.write(inventory_content)
        tmp_inventory.close()
        os.chmod(tmp_inventory.name, 0o600)  # restrict file perms

        def stream_logs():
            cmd = ["ansible-playbook", "-i", tmp_inventory.name, "deploy_nessus_agent.yml"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in iter(process.stdout.readline, b""):
                yield f"data:{line.decode()}\n"
            process.stdout.close()
            rc = process.wait()
            yield f"data:PLAYBOOK_EXIT={rc}\n"
            os.unlink(tmp_inventory.name)

        return Response(stream_logs(), mimetype='text/event-stream')

    return render_template("index.html", predefined_accounts=PREDEFINED_ACCOUNTS)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, debug=True)
