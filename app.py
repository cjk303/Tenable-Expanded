import os
import sqlite3
import subprocess
import json
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, g, flash

app = Flask(__name__)
app.secret_key = "super-secret-key"

# Database path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "deployments.db")

# Ensure DB folder exists
os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)


def get_db():
    """Get a SQLite connection"""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    """Close DB connection at end of request"""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create table if it doesn't exist"""
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

        # For demo, we accept any password if not empty
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
# DEPLOY PAGE
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
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    cmd = [
        "ansible-playbook",
        "deploy_nessus_agent.yml",
        "-i",
        "inventory.ini",
        "-e",
        f"escalate_method={escalate_method}",
        "--json",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as e:
        flash(f"Error running Ansible: {e}", "danger")
        return redirect(url_for("index"))

    # Parse JSON output
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        flash("Could not parse Ansible output (JSON error).", "danger")
        return redirect(url_for("index"))

    db = get_db()

    # Walk through hosts
    for host, data in parsed.get("stats", {}).items():
        rapid7_removed = 1 if data.get("changed", 0) > 0 else 0
        agent_installed = 1 if data.get("ok", 0) > 0 else 0
        errors = None
        if data.get("failures", 0) > 0:
            errors = "Some tasks failed"

        db.execute(
            "INSERT INTO deployment_results (run_id, hostname, rapid7_removed, agent_installed, errors) VALUES (?, ?, ?, ?, ?)",
            (timestamp, host, rapid7_removed, agent_installed, errors),
        )
    db.commit()

    flash("Deployment completed and results saved.", "success")
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
