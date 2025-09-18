#!/usr/bin/env python3
from flask import (
    Flask, render_template, request, Response,
    redirect, url_for, session, flash
)
from ldap3 import Server, Connection, SIMPLE, ALL
from functools import wraps
import os
import json
import tempfile
import subprocess
from cryptography.fernet import Fernet
from pathlib import Path
import shlex

app = Flask(__name__)

# 🔑 Use a strong random secret key in production (set via env).
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super-secret-key")

# LDAP domain (update as needed)
LDAP_DOMAIN = "amer.epiqcorp.com"

# ------------------ LDAP AUTH ------------------ #
def authenticate_user(username, password):
    """
    Simple bind to LDAP (LDAPS on port 636).
    Returns True if bind succeeds, False otherwise.
    """
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
    # Predefined accounts file
    PREDEFINED_FILE = "predefined_accounts.json"
    if not os.path.isfile(PREDEFINED_FILE):
        open(PREDEFINED_FILE, "w").write("{}")

    with open(PREDEFINED_FILE) as f:
        try:
            PREDEFINED_ACCOUNTS = json.load(f)
        except Exception:
            PREDEFINED_ACCOUNTS = {}

    # Load Fernet key (must be created beforehand)
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
        use_predefined = bool(account_key and account_key in PREDEFINED_ACCOUNTS)

        if use_predefined:
            account = PREDEFINED_ACCOUNTS[account_key]
            username = account.get("username", "")
            password = decrypt_password(account.get("password", ""))
            sudo_password = decrypt_password(account.get("sudo_password", ""))
            activation_key = account.get("activation_key", "")
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            sudo_password = request.form.get("sudo_password", "").strip()
            activation_key = request.form.get("activation_key", "").strip()

        if not username or not password or not activation_key:
            return "Error: username, password, and activation key are required.", 400

        # Hosts: accept a newline-separated list; strip blanks
        raw_hosts = request.form.get("hosts", "")
        hosts = [h.strip() for h in raw_hosts.splitlines() if h.strip()]
        if not hosts:
            return "Error: at least one host is required.", 400

        groups = request.form.get("groups", "")
        mode = request.form.get("mode", "cloud")
        manager_host = request.form.get("manager_host", "")
        manager_port = request.form.get("manager_port", "8834")
        escalate_method = request.form.get("escalate_method", "sudo")  # supports 'sudo', 'dzdo', etc.
        # Convert checkbox-like inputs to explicit booleans
        remove_rapid7_flag = bool(request.form.get("remove_rapid7"))

        # Build ephemeral Ansible inventory (INI-style)
        # Quote values that may contain spaces or special chars.
        def q(v):
            # simple quoting that avoids double quoting already quoted strings
            if v is None:
                return "''"
            s = str(v)
            if s.startswith("'") and s.endswith("'"):
                return s
            # shlex.quote would put single-quotes around; use that to be safer
            return shlex.quote(s)

        inventory_lines = []
        inventory_lines.append("[agents]")
        inventory_lines.extend(hosts)
        inventory_lines.append("")  # blank line
        inventory_lines.append("[agents:vars]")
        inventory_lines.append(f"ansible_user={q(username)}")
        inventory_lines.append(f"ansible_password={q(password)}")
        inventory_lines.append(f"ansible_become_password={q(sudo_password)}")
        inventory_lines.append(f"ansible_become_method={escalate_method}")
        inventory_lines.append(f"activation_key={q(activation_key)}")
        inventory_lines.append(f"groups={q(groups)}")
        inventory_lines.append(f"mode={q(mode)}")
        inventory_lines.append(f"manager_host={q(manager_host)}")
        inventory_lines.append(f"manager_port={manager_port}")
        inventory_lines.append(f"remove_rapid7={str(remove_rapid7_flag).lower()}")
        inventory_content = "\n".join(inventory_lines) + "\n"

        # Write temp inventory file with secure permissions
        tmp_inventory = tempfile.NamedTemporaryFile(delete=False, mode="w")
        try:
            tmp_inventory.write(inventory_content)
            tmp_inventory.close()
            os.chmod(tmp_inventory.name, 0o600)
        except Exception:
            # cleanup if write failed
            try:
                os.unlink(tmp_inventory.name)
            except Exception:
                pass
            raise

        # Stream ansible-playbook output as server-sent events
        def stream_logs():
            cmd = [
                "ansible-playbook",
                "-vvvv",  # helpful for debugging; remove or lower verbosity in prod
                "-i", tmp_inventory.name,
                "deploy_nessus_agent.yml"
            ]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            try:
                # iterate over stdout lines until EOF
                for line in iter(process.stdout.readline, ''):
                    if line == '':
                        break
                    # yield each line as an SSE data event
                    yield f"data:{line}\n"
            except Exception as e:
                app.logger.exception(f"Error while streaming ansible output: {e}")
            finally:
                try:
                    if process.stdout:
                        process.stdout.close()
                except Exception:
                    pass
                rc = process.wait()
                # final event with exit code
                yield f"data:PLAYBOOK_EXIT={rc}\n"
                # remove inventory file
                try:
                    os.unlink(tmp_inventory.name)
                except Exception:
                    app.logger.warning(f"Failed to remove temp inventory {tmp_inventory.name}")

        return Response(stream_logs(), mimetype='text/event-stream')

    return render_template("index.html", predefined_accounts=PREDEFINED_ACCOUNTS)


if __name__ == "__main__":
    # NOTE: debug=True is convenient during development but should be disabled in production.
    app.run(host="0.0.0.0", port=8443, debug=True)
