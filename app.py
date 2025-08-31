import os
import sqlite3
import subprocess
import json
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, g, flash

app = Flask(__name__)
app.secret_key = "super-secret-key"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "deployments.db")
os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS deployment_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            hostname TEXT,
            rapid7_removed INTEGER,
            agent_installed INTEGER,
            errors TEXT
        )
        """
    )
    db.commit()


@app.before_request
def before_request():
    init_db()


# ----------------------
# AUTH
# ----------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Demo auth (replace with real LDAP bind if needed)
        if username and password:
            session["username"] = username
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ----------------------
# DEPLOY
# ----------------------
@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/deploy", methods=["POST"])
def deploy():
    if "username" not in session:
        return redirect(url_for("login"))

    escalate_method = request.form.get("escalate", "sudo")
    run_id = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    cmd = [
        "ansible-playbook",
        "deploy_nessus_agent.yml",
        "-i",
        "inventory.ini",
        "-e",
        f"escalate_method={escalate_method}",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as e:
        flash(f"Error running Ansible: {e}", "danger")
        return redirect(url_for("index"))

    db = get_db()
    errors_global = None

    # Parse output by scanning debug lines
    for line in result.stdout.splitlines():
        if '"hostname":' in line:
            try:
                data = json.loads(line.split("=>")[-1].strip())
                hostname = data.get("hostname")
                rapid7_removed = 1 if data.get("rapid7_removed") else 0
                agent_installed = 1 if data.get("agent_installed") else 0
                db.execute(
                    "INSERT INTO deployment_results (run_id, hostname, rapid7_removed, agent_installed, errors) VALUES (?, ?, ?, ?, ?)",
                    (run_id, hostname, rapid7_removed, agent_installed, None),
                )
            except Exception as e:
                errors_global = f"JSON parse error: {e}"

    if errors_global:
        flash(errors_global, "danger")
    else:
        flash("Deployment finished and results saved.", "success")

    db.commit()
    return redirect(url_for("history"))


# ----------------------
# HISTORY
# ----------------------
@app.route("/history")
def history():
    if "username" not in session:
        return redirect(url_for("login"))

    db = get_db()
    runs = db.execute(
        "SELECT run_id, hostname, rapid7_removed, agent_installed, errors FROM deployment_results ORDER BY id DESC"
    ).fetchall()
    return render_template("history.html", runs=runs)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, debug=True)
