from __future__ import annotations

import base64
import os
import pickle
import re
import sqlite3
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote, urlparse

from flask import Flask, Response, g, jsonify, redirect, render_template, request, url_for

from db import DATA_DIR, DB_PATH, STATEMENTS_DIR, bootstrap, connect, fetch_all, fetch_one, run

bootstrap()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.update(
    SECRET_KEY="bank-lab-secret-2026",
    SESSION_COOKIE_HTTPONLY=False,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE=None,
    TEMPLATES_AUTO_RELOAD=True,
    DEBUG=True,
)

ADMIN_UNLOCK_KEY = "bank-admin-unlock-2026"


@app.after_request
def add_vulnerable_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.before_request
def load_current_user():
    user_id = request.cookies.get("bank_uid")
    g.current_user = None
    if user_id and user_id.isdigit():
        g.current_user = fetch_one("SELECT * FROM users WHERE id = ?", (int(user_id),))


@app.route("/")
def index():
    stats = fetch_one(
        """
        SELECT
            (SELECT COUNT(*) FROM users) AS user_count,
            (SELECT COUNT(*) FROM accounts) AS account_count,
            (SELECT COALESCE(SUM(balance), 0) FROM accounts) AS total_assets,
            (SELECT COUNT(*) FROM tickets) AS ticket_count
        """
    )
    return render_template("index.html", stats=stats, current_user=g.current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        query = f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'"
        try:
            conn = connect()
            user = conn.execute(query).fetchone()
            conn.close()
            if user:
                response = redirect(url_for("dashboard"))
                response.set_cookie("bank_uid", str(user["id"]), httponly=False, secure=False)
                return response
            error = "Invalid credentials"
        except sqlite3.Error as exc:
            error = f"Authentication error: {exc}"
    return render_template("login.html", error=error, current_user=g.current_user)


@app.route("/logout")
def logout():
    next_url = request.args.get("next", url_for("index"))
    response = redirect(next_url)
    response.delete_cookie("bank_uid")
    return response


@app.route("/dashboard")
def dashboard():
    user_id = request.args.get("user_id") or (g.current_user["id"] if g.current_user else None)
    if not user_id:
        return redirect(url_for("login"))
    user_id = int(user_id)
    user = fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
    accounts = fetch_all("SELECT * FROM accounts WHERE user_id = ?", (user_id,))
    tickets = fetch_all("SELECT * FROM tickets WHERE user_id = ? ORDER BY id DESC", (user_id,))
    recent = fetch_all(
        """
        SELECT t.*, a.account_no
        FROM transactions t
        JOIN accounts a ON a.id = t.account_id
        WHERE a.user_id = ?
        ORDER BY t.id DESC
        LIMIT 6
        """,
        (user_id,),
    )
    search_query = request.args.get("q", "")
    search_results = []
    if search_query:
        search_sql = (
            "SELECT * FROM transactions WHERE note LIKE '%"
            + search_query
            + "%' OR counterparty LIKE '%"
            + search_query
            + "%'"
        )
        try:
            conn = connect()
            search_results = conn.execute(search_sql).fetchall()
            conn.close()
        except sqlite3.Error as exc:
            search_results = [{"counterparty": "SQL error", "note": str(exc), "amount": 0, "created_at": ""}]
    stats = fetch_one(
        "SELECT COUNT(*) AS account_total, COALESCE(SUM(balance), 0) AS balance_total FROM accounts WHERE user_id = ?",
        (user_id,),
    )
    return render_template(
        "dashboard.html",
        user=user,
        accounts=accounts,
        tickets=tickets,
        recent=recent,
        stats=stats,
        search_query=search_query,
        search_results=search_results,
        current_user=g.current_user,
    )


@app.route("/reflect")
def reflect():
    message = request.args.get("message", "Welcome to the customer notice board")
    name = request.args.get("name", "guest")
    return render_template(
        "reflect.html",
        message=message,
        name=name,
        current_user=g.current_user,
    )


@app.route("/sql-lab")
def sql_lab():
    item_id = request.args.get("id", "1")
    raw_query = f"SELECT * FROM users WHERE id = {item_id}"
    try:
        conn = connect()
        row = conn.execute(raw_query).fetchone()
        conn.close()
        return jsonify(
            {
                "query": raw_query,
                "result": dict(row) if row else None,
                "hint": "Endpoint intentionally unsafe for scanner testing",
            }
        )
    except sqlite3.Error as exc:
        return Response(
            f"sqlite3.OperationalError: {exc}\nquery={raw_query}",
            status=500,
            mimetype="text/plain",
        )


@app.route("/account/<int:account_id>")
def account_detail(account_id: int):
    account = fetch_one("SELECT * FROM accounts WHERE id = ?", (account_id,))
    if not account:
        return redirect(url_for("dashboard"))
    transactions = fetch_all(
        "SELECT * FROM transactions WHERE account_id = ? ORDER BY id DESC",
        (account_id,),
    )
    return render_template(
        "account.html",
        account=account,
        transactions=transactions,
        current_user=g.current_user,
    )


@app.route("/transfer", methods=["POST"])
def transfer():
    from_account = request.form.get("from_account", "")
    to_account = request.form.get("to_account", "")
    amount = request.form.get("amount", "0")
    note = request.form.get("note", "")
    sql = f"INSERT INTO transactions (account_id, counterparty, amount, note, created_at) VALUES ({from_account}, 'TRANSFER', -{amount}, '{note}', datetime('now'))"
    sql2 = f"UPDATE accounts SET balance = balance - {amount} WHERE id = {from_account}"
    sql3 = f"UPDATE accounts SET balance = balance + {amount} WHERE id = {to_account}"
    conn = connect()
    try:
        conn.execute(sql)
        conn.execute(sql2)
        conn.execute(sql3)
        conn.commit()
    except sqlite3.Error:
        conn.close()
        return render_template("support.html", current_user=g.current_user, tickets=[], transfer_error="Transfer failed")
    conn.close()
    return redirect(url_for("dashboard", user_id=request.args.get("user_id", "1")))


@app.route("/support", methods=["GET", "POST"])
def support():
    message = None
    if request.method == "POST":
        subject = request.form.get("subject", "General")
        body = request.form.get("body", "")
        user_id = int(request.form.get("user_id", g.current_user["id"] if g.current_user else 1))
        conn = connect()
        conn.execute(
            "INSERT INTO tickets (user_id, subject, body, created_at) VALUES (?, ?, ?, datetime('now'))",
            (user_id, subject, body),
        )
        conn.commit()
        conn.close()
        message = "Ticket created"
    tickets = fetch_all("SELECT t.*, u.name FROM tickets t JOIN users u ON u.id = t.user_id ORDER BY t.id DESC")
    return render_template("support.html", tickets=tickets, message=message, current_user=g.current_user)


@app.route("/redirect")
def unsafe_redirect():
    next_url = request.args.get("next", url_for("index"))
    return redirect(next_url)


@app.route("/fetch")
def fetch_remote():
    target = request.args.get("url", "http://127.0.0.1:5000/")
    with urllib.request.urlopen(target, timeout=3) as handle:
        body = handle.read(3000).decode("utf-8", errors="replace")
    return Response(body, mimetype="text/plain")


@app.route("/download")
def download_statement():
    filename = request.args.get("file", "ACC-100001.txt")
    path = STATEMENTS_DIR / filename
    content = path.read_text(encoding="utf-8", errors="replace")
    return Response(content, mimetype="text/plain")


@app.route("/api/profile/<int:user_id>")
def api_profile(user_id: int):
    user = fetch_one("SELECT id, name, email, role, ssn FROM users WHERE id = ?", (user_id,))
    return jsonify(dict(user) if user else {"error": "not found"})


@app.route("/api/invoice/<int:invoice_id>")
def api_invoice(invoice_id: int):
    invoices = {
        1: {"invoice_id": 1, "owner_id": 1, "amount": 18200.25, "status": "PAID"},
        2: {"invoice_id": 2, "owner_id": 2, "amount": 9875.00, "status": "DUE"},
        3: {"invoice_id": 3, "owner_id": 3, "amount": 50210.75, "status": "OVERDUE"},
    }
    return jsonify(invoices.get(invoice_id, {"error": "not found"}))


@app.route("/api/restore-session", methods=["POST"])
def restore_session():
    payload = request.get_data(as_text=True) or request.form.get("payload", "")
    try:
        decoded = base64.b64decode(payload)
        session_object = pickle.loads(decoded)
        return jsonify({"status": "restored", "object": repr(session_object)})
    except Exception as exc:
        return jsonify({"status": "error", "detail": str(exc)}), 400


@app.route("/api/import-xml", methods=["POST"])
def import_xml():
    raw_xml = request.get_data(as_text=True) or request.form.get("xml", "")
    leaked = {}
    entity_matches = re.findall(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+["\']file://([^"\']+)["\']>', raw_xml, flags=re.I)
    for name, file_path in entity_matches:
        try:
            leaked[name] = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            leaked[name] = ""
    for name, content in leaked.items():
        raw_xml = raw_xml.replace(f"&{name};", content)
    root = ET.fromstring(raw_xml)
    return jsonify({"root": root.tag, "text": root.text or "", "children": [child.tag for child in root]})


@app.route("/admin/console")
def admin_console():
    debug_bypass = request.args.get("debug") == "1"
    admin_key = request.args.get("key") == ADMIN_UNLOCK_KEY
    if not debug_bypass and not admin_key and not (g.current_user and g.current_user["role"] == "admin"):
        return redirect(url_for("login"))

    cmd = request.args.get("cmd", "status")
    shell_cmd = f"echo Reconciled ledger for {cmd}"
    proc = subprocess.run(shell_cmd, shell=True, capture_output=True, text=True)
    summary = fetch_one(
        "SELECT COUNT(*) AS users, (SELECT COUNT(*) FROM accounts) AS accounts, (SELECT COUNT(*) FROM tickets) AS tickets FROM users"
    )
    config_dump = {
        "secret_key": app.config["SECRET_KEY"],
        "db_path": str(DB_PATH),
        "statements_dir": str(STATEMENTS_DIR),
        "debug": app.debug,
    }
    return render_template(
        "admin.html",
        summary=summary,
        command_output=proc.stdout + proc.stderr,
        config_dump=config_dump,
        current_user=g.current_user,
    )


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin/console\nDisallow: /debug/config\nDisallow: /api/restore-session\n", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    xml = """<?xml version='1.0' encoding='UTF-8'?>
<urlset>
  <url><loc>/</loc></url>
  <url><loc>/login</loc></url>
  <url><loc>/dashboard</loc></url>
  <url><loc>/support</loc></url>
  <url><loc>/admin/console</loc></url>
  <url><loc>/debug/config</loc></url>
</urlset>"""
    return Response(xml, mimetype="application/xml")


@app.route("/debug/config")
def debug_config():
    return jsonify(
        {
            "secret_key": app.config["SECRET_KEY"],
            "db_path": str(DB_PATH),
            "statements_dir": str(STATEMENTS_DIR),
            "current_user": dict(g.current_user) if g.current_user else None,
        }
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok", "mode": "lab", "db": str(DB_PATH)})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
