#!/usr/bin/env python3
from flask import Flask, render_template, request, Response, redirect, url_for, session, flash
from ldap3 import Server, Connection, SIMPLE, ALL
from functools import wraps
import os, json, tempfile, subprocess, shlex, sys
from cryptography.fernet import Fernet
import paramiko

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super-secret-key")

LDAP_DOMAIN = "amer.epiqcorp.com"

# ------------------ LDAP AUTH ------------------ #
def authenticate_user(username, password):
    user_principal = f"{username}@{LDAP_DOMAIN}"
    server = Server(LDAP_DOMAIN, get_info=ALL, port=636, use_ssl=True)
    try:
        conn = Connection(server, user=user_principal, password=password,
                          authentication=SIMPLE, auto_bind=True)
        conn.unbind()
        return True
    except Exception as e:
        app.logger.warning(f"LDAP auth failed for {user_principal}: {e}")
        return False

# ------------------ LOGIN REQUIRED ------------------ #
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
        try:
            PREDEFINED_ACCOUNTS = json.load(f)
        except Exception:
            PREDEFINED_ACCOUNTS = {}

    # Load Fernet key
    KEY_FILE = "fernet.key"
    if not os.path.isfile(KEY_FILE):
        raise FileNotFoundError(f"Fernet key file '{KEY_FILE}' not found.")
    with open(KEY_FILE, "r") as kf:
        ENCRYPTION_KEY = kf.read().strip()
    cipher = Fernet(ENCRYPTION_KEY.encode())

    def decrypt_password(enc_password):
        return cipher.decrypt(enc_password.encode()).decode()

    if request.method == "POST":
        account_key = request.form.get("predefined_account")
        use_predefined = bool(account_key and account_key in PREDEFINED_ACCOUNTS)

        if use_predefined:
            account = PREDEFINED_ACCOUNTS[account_key]
            username = account.get("username", "")
            password = decrypt_password(account.get("password", ""))
            sudo_password = decrypt_password(account.get("sudo_password", ""))
            activation_key = account.get("activation_key", "")
            escalate_method = account.get("escalate_method", "sudo")
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            sudo_password = request.form.get("sudo_password", "").strip()
            activation_key = request.form.get("activation_key", "").strip()
            escalate_method = request.form.get("escalate_method", "sudo")
            if not username or not password or not activation_key:
                return "Error: username, password, and activation key are required.", 400

        hosts = [h.strip() for h in request.form.get("hosts", "").splitlines() if h.strip()]
        if not hosts:
            return "Error: at least one host is required.", 400

        groups = request.form.get("groups", "")
        mode = request.form.get("mode", "cloud")
        manager_host = request.form.get("manager_host", "")
        manager_port = request.form.get("manager_port", "8834")
        remove_rapid7_flag = bool(request.form.get("remove_rapid7"))

        # ----------------- Pre-flight SSH/Sudo/dzdo check ----------------- #
        if not use_predefined:
            for host in hosts:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(
                        hostname=host,
                        username=username,
                        password=password,
                        timeout=5
                    )

                    # Safely escape password for shell
                    escaped_password = shlex.quote(sudo_password)

                    if escalate_method == "sudo":
                        cmd = f"echo {escaped_password} | sudo -S whoami"
                    elif escalate_method == "dzdo":
                        cmd = f"echo {escaped_password} | dzdo -S whoami"
                    else:
                        cmd = "whoami"

                    stdin, stdout, stderr = client.exec_command(cmd)
                    result = stdout.read().decode().strip()
                    err = stderr.read().decode().strip()
                    client.close()

                    if result != "root":
                        return f"Error: {escalate_method} test failed on {host}. Check password or privileges.\n{err}", 400

                except Exception as e:
                    return f"Error: SSH connection failed to {host}: {str(e)}", 400

        # ---------------- Inventory generation ---------------- #
        def safe_value(v):
            if v is None:
                return "''"
            return shlex.quote(str(v))

        if escalate_method not in ["sudo", "dzdo", "su"]:
            escalate_method = "sudo"

        inventory_lines = []
        inventory_lines.append("[agents]")
        inventory_lines.extend(hosts)
        inventory_lines.append("")
        inventory_lines.append("[agents:vars]")
        inventory_lines.append(f"ansible_user={safe_value(username)}")
        inventory_lines.append(f"ansible_password={safe_value(password)}")
        inventory_lines.append(f"ansible_become_password={safe_value(sudo_password)}")
        inventory_lines.append(f"ansible_become_method={escalate_method}")
        inventory_lines.append(f"activation_key={safe_value(activation_key)}")
        inventory_lines.append(f"groups={safe_value(groups)}")
        inventory_lines.append(f"mode={safe_value(mode)}")
        inventory_lines.append(f"manager_host={safe_value(manager_host)}")
        inventory_lines.append(f"manager_port={manager_port}")
        inventory_lines.append(f"remove_rapid7={str(remove_rapid7_flag).lower()}")
        inventory_lines.append("ansible_ssh_common_args='-o PreferredAuthentications=password -o PubkeyAuthentication=no'")
        inventory_lines.append("ansible_become_flags='-tt'")

        inventory_content = "\n".join(inventory_lines) + "\n"
        tmp_inventory = tempfile.NamedTemporaryFile(delete=False, mode="w")
        tmp_inventory.write(inventory_content)
        tmp_inventory.close()
        os.chmod(tmp_inventory.name, 0o600)

        # Mask passwords in logs
        masked_inventory = []
        for line in inventory_lines:
            if "password" in line.lower():
                masked_inventory.append(line.split("=")[0] + "=****")
            else:
                masked_inventory.append(line)
        app.logger.info("Ansible inventory being used:\n%s", "\n".join(masked_inventory))

        # ---------------- Stream logs ---------------- #
        def stream_logs():
            cmd = [
                "ansible-playbook",
                "-i", tmp_inventory.name,
                "deploy_nessus_agent.yml"
            ]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            try:
                for line in iter(process.stdout.readline, ''):
                    yield f"data:{line.rstrip()}\n\n"
                    sys.stdout.flush()
            finally:
                process.stdout.close()
                rc = process.wait()
                yield f"data:PLAYBOOK_EXIT={rc}\n\n"
                sys.stdout.flush()
                try:
                    os.unlink(tmp_inventory.name)
                except Exception:
                    app.logger.warning(f"Failed to remove temp inventory {tmp_inventory.name}")

        return Response(stream_logs(), mimetype='text/event-stream')

    return render_template("index.html", predefined_accounts=PREDEFINED_ACCOUNTS)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, debug=True)
