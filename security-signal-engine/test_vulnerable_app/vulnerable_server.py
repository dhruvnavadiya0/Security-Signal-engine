"""
Intentionally Vulnerable Flask Web Application
===============================================

This app is designed to demonstrate ALL the security vulnerabilities
that the Security Signal Engine can detect, especially the new features:

  1. Adaptive Rate Limiter    → Endpoints that respond slowly under load
  2. Smart Crawler            → Infinite pagination loops
  3. Traffic Store             → Mix of static assets + dynamic pages
  4. OAST Detector             → Blind SSRF endpoint
  5. False Positive Filter     → Generic error pages that trigger FPs
  6. Plugin Manager            → Custom scanner plugin demo

  STANDARD VULNERABILITIES:
  - SQL Injection (error-based + form-based)
  - Reflected XSS
  - Stored XSS
  - Open Redirect
  - SSRF (direct + blind)
  - Path Traversal
  - Missing Security Headers
  - Insecure Cookies
  - CORS Misconfiguration
  - Information Disclosure
  - Directory Listing
  - Dangerous HTTP Methods
  - XXE
  - IDOR

⚠️  DO NOT deploy this app to production. It is intentionally insecure.
"""

import os
import sqlite3
import time
import random
import urllib.request
from pathlib import Path
from flask import (
    Flask, request, redirect, Response,
    render_template_string, jsonify, send_from_directory,
    make_response,
)

app = Flask(__name__)

# ── Database Setup ─────────────────────────────────────────
DB_PATH = Path(__file__).parent / "vulnerable.db"


def init_db():
    """Initialize the vulnerable SQLite database."""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            comment TEXT NOT NULL,
            page TEXT DEFAULT 'main'
        )
    """)
    # Seed some data
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            [
                ("admin", "admin123", "admin@example.com", "admin"),
                ("john", "password", "john@example.com", "user"),
                ("jane", "secret", "jane@example.com", "user"),
                ("testuser", "test", "test@example.com", "user"),
            ],
        )
    conn.commit()
    conn.close()


init_db()

# ── LAYOUT TEMPLATE ────────────────────────────────────────
LAYOUT = """<!DOCTYPE html>
<html>
<head>
    <title>VulnApp - {{ title }}</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px;">
    <nav style="background: #333; padding: 10px; margin-bottom: 20px;">
        <a href="/" style="color: white; margin-right: 15px;">Home</a>
        <a href="/search" style="color: white; margin-right: 15px;">Search</a>
        <a href="/users" style="color: white; margin-right: 15px;">Users</a>
        <a href="/comments" style="color: white; margin-right: 15px;">Comments</a>
        <a href="/profile/1" style="color: white; margin-right: 15px;">Profile</a>
        <a href="/admin" style="color: white; margin-right: 15px;">Admin</a>
        <a href="/upload" style="color: white; margin-right: 15px;">Upload</a>
        <a href="/api/data" style="color: white; margin-right: 15px;">API</a>
        <a href="/page/1" style="color: white; margin-right: 15px;">Page 1</a>
        <a href="/products" style="color: white; margin-right: 15px;">Products</a>
    </nav>
    <h1>{{ title }}</h1>
    {{ content }}
</body>
</html>"""


# ═══════════════════════════════════════════════════════════
#  HOME PAGE — information disclosure + missing headers
# ═══════════════════════════════════════════════════════════

@app.route("/")
def home():
    # ❌ Missing security headers (X-Frame-Options, CSP, etc.)
    # ❌ Server version disclosure
    resp = make_response(render_template_string(LAYOUT, title="Home", content="""
        <p>Welcome to VulnApp — an intentionally vulnerable application.</p>
        <h2>Navigation</h2>
        <ul>
            <li><a href="/search?q=test">Search (XSS)</a></li>
            <li><a href="/users?id=1">User Lookup (SQLi)</a></li>
            <li><a href="/comments">Comment Board (Stored XSS)</a></li>
            <li><a href="/redirect?url=https://google.com">Redirect (Open Redirect)</a></li>
            <li><a href="/fetch?url=http://example.com">Fetch URL (SSRF)</a></li>
            <li><a href="/file?path=readme.txt">Read File (Path Traversal)</a></li>
            <li><a href="/profile/1">Profile (IDOR)</a></li>
            <li><a href="/page/1">Paginated (Crawler Loop)</a></li>
            <li><a href="/products">Products (Crawler Loop)</a></li>
            <li><a href="/api/xml">XML API (XXE)</a></li>
        </ul>
        <!-- TODO: Remove debug info before production -->
        <!-- DB_PATH: """ + str(DB_PATH) + """ -->
        <!-- Server: Python/Flask DEBUG MODE -->
        <!-- API Key: sk-test-1234567890abcdef -->
    """))
    # ❌ Information disclosure via headers
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    resp.headers["X-Powered-By"] = "Flask/2.0.1 Python/3.10.0"
    # ❌ Insecure cookie
    resp.set_cookie("session_id", "abc123", httponly=False, secure=False, samesite=None)
    resp.set_cookie("user_token", "eyJhbGciOiJIUzI1NiJ9.test", httponly=False)
    return resp


# ═══════════════════════════════════════════════════════════
#  SQL INJECTION — error-based via query parameter
# ═══════════════════════════════════════════════════════════

@app.route("/users")
def users():
    """❌ SQL Injection: User input directly concatenated into SQL."""
    user_id = request.args.get("id", "")
    content = "<h2>User Lookup</h2>"
    content += '<form action="/users" method="get">'
    content += '<input name="id" placeholder="Enter user ID" value="' + user_id + '">'
    content += '<button type="submit">Search</button></form>'

    if user_id:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        try:
            # ❌ VULNERABLE: Direct string concatenation in SQL
            query = f"SELECT * FROM users WHERE id = {user_id}"
            cursor.execute(query)
            rows = cursor.fetchall()
            if rows:
                content += "<table border='1' style='margin-top:10px'>"
                content += "<tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>"
                for row in rows:
                    content += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[3]}</td><td>{row[4]}</td></tr>"
                content += "</table>"
            else:
                content += "<p>No user found.</p>"
        except Exception as e:
            # ❌ Database error message exposed to user (confirms SQLi)
            content += f"<p style='color:red'>Database error: {e}</p>"
        conn.close()

    return render_template_string(LAYOUT, title="Users", content=content)


# ═══════════════════════════════════════════════════════════
#  SQL INJECTION — form-based via POST
# ═══════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    """❌ SQL Injection via POST form fields."""
    content = """
    <h2>Login</h2>
    <form action="/login" method="post">
        <input name="username" placeholder="Username"><br><br>
        <input name="password" type="password" placeholder="Password"><br><br>
        <button type="submit">Login</button>
    </form>
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        try:
            # ❌ VULNERABLE: Direct string formatting in SQL
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                content += f"<p style='color:green'>Welcome, {user[1]}!</p>"
            else:
                content += "<p style='color:red'>Invalid credentials.</p>"
        except Exception as e:
            content += f"<p style='color:red'>SQL Error: {e}</p>"
        conn.close()

    return render_template_string(LAYOUT, title="Login", content=content)


# ═══════════════════════════════════════════════════════════
#  REFLECTED XSS — search parameter
# ═══════════════════════════════════════════════════════════

@app.route("/search")
def search():
    """❌ Reflected XSS: User input rendered directly in HTML."""
    query = request.args.get("q", "")
    # ❌ VULNERABLE: No output encoding/escaping
    content = f"""
    <h2>Search</h2>
    <form action="/search" method="get">
        <input name="q" placeholder="Search..." value="{query}">
        <button type="submit">Search</button>
    </form>
    <p>Results for: {query}</p>
    <p>No results found for your query.</p>
    """
    return render_template_string(LAYOUT, title="Search", content=content)


# ═══════════════════════════════════════════════════════════
#  STORED XSS — comment board
# ═══════════════════════════════════════════════════════════

@app.route("/comments", methods=["GET", "POST"])
def comments():
    """❌ Stored XSS: Comments stored and displayed without sanitization."""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    if request.method == "POST":
        username = request.form.get("username", "anonymous")
        comment = request.form.get("comment", "")
        if comment:
            # ❌ VULNERABLE: Storing raw user input without sanitization
            cursor.execute(
                "INSERT INTO comments (username, comment) VALUES (?, ?)",
                (username, comment),
            )
            conn.commit()

    cursor.execute("SELECT username, comment FROM comments ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()
    conn.close()

    comments_html = ""
    for row in rows:
        # ❌ VULNERABLE: Rendering stored content without escaping
        comments_html += f"<div style='border:1px solid #ccc; padding:10px; margin:5px'>"
        comments_html += f"<strong>{row[0]}</strong>: {row[1]}</div>"

    content = f"""
    <h2>Comment Board</h2>
    <form action="/comments" method="post">
        <input name="username" placeholder="Your name"><br><br>
        <textarea name="comment" placeholder="Write a comment..." rows="3" cols="50"></textarea><br><br>
        <button type="submit">Post Comment</button>
    </form>
    <h3>Recent Comments</h3>
    {comments_html}
    """
    return render_template_string(LAYOUT, title="Comments", content=content)


# ═══════════════════════════════════════════════════════════
#  OPEN REDIRECT
# ═══════════════════════════════════════════════════════════

@app.route("/redirect")
def open_redirect():
    """❌ Open Redirect: Redirects to any URL provided by the user."""
    url = request.args.get("url", "/")
    # ❌ VULNERABLE: No validation of redirect target
    return redirect(url)


# ═══════════════════════════════════════════════════════════
#  SSRF — Server-Side Request Forgery
# ═══════════════════════════════════════════════════════════

@app.route("/fetch")
def fetch_url():
    """❌ SSRF: Server fetches any URL provided by the user."""
    url = request.args.get("url", "")
    content = """
    <h2>URL Fetcher</h2>
    <form action="/fetch" method="get">
        <input name="url" placeholder="Enter URL to fetch" style="width:400px" value="">
        <button type="submit">Fetch</button>
    </form>
    """
    if url:
        try:
            # ❌ VULNERABLE: No URL validation, allows internal network access
            resp = urllib.request.urlopen(url, timeout=5)
            body = resp.read(4096).decode("utf-8", errors="replace")
            content += f"<h3>Response from {url}:</h3>"
            content += f"<pre>{body[:2000]}</pre>"
        except Exception as e:
            content += f"<p style='color:red'>Fetch error: {e}</p>"

    return render_template_string(LAYOUT, title="URL Fetcher", content=content)


# ═══════════════════════════════════════════════════════════
#  PATH TRAVERSAL
# ═══════════════════════════════════════════════════════════

@app.route("/file")
def read_file():
    """❌ Path Traversal: Reads any file on the server."""
    file_path = request.args.get("path", "")
    content = """
    <h2>File Reader</h2>
    <form action="/file" method="get">
        <input name="path" placeholder="Enter filename" value="">
        <button type="submit">Read</button>
    </form>
    """
    if file_path:
        try:
            # ❌ VULNERABLE: No path sanitization, allows ../../etc/passwd
            base_dir = Path(__file__).parent / "files"
            full_path = base_dir / file_path
            with open(full_path, "r") as f:
                file_content = f.read()
            content += f"<h3>Contents of {file_path}:</h3>"
            content += f"<pre>{file_content}</pre>"
        except Exception as e:
            content += f"<p style='color:red'>Error: {e}</p>"

    return render_template_string(LAYOUT, title="File Reader", content=content)


# ═══════════════════════════════════════════════════════════
#  IDOR — Insecure Direct Object Reference
# ═══════════════════════════════════════════════════════════

@app.route("/profile/<int:user_id>")
def profile(user_id):
    """❌ IDOR: Any user profile accessible without authentication."""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        # ❌ VULNERABLE: No authorization check — any user can view any profile
        content = f"""
        <h2>User Profile</h2>
        <table border="1" cellpadding="8">
            <tr><td><strong>ID</strong></td><td>{user[0]}</td></tr>
            <tr><td><strong>Username</strong></td><td>{user[1]}</td></tr>
            <tr><td><strong>Password</strong></td><td>{user[2]}</td></tr>
            <tr><td><strong>Email</strong></td><td>{user[3]}</td></tr>
            <tr><td><strong>Role</strong></td><td>{user[4]}</td></tr>
        </table>
        <p><a href="/profile/{user_id + 1}">Next Profile →</a></p>
        <p><a href="/profile/{max(user_id - 1, 1)}">← Previous Profile</a></p>
        """
    else:
        content = "<p>User not found.</p>"

    return render_template_string(LAYOUT, title=f"Profile #{user_id}", content=content)


# ═══════════════════════════════════════════════════════════
#  INFINITE PAGINATION — triggers Smart Crawler loop detection
# ═══════════════════════════════════════════════════════════

@app.route("/page/<int:page_num>")
def paginated(page_num):
    """
    ❌ Infinite pagination: generates links to page N+1 forever.
    This is what causes ZAP's spider to loop infinitely.
    The Smart Crawler detects /page/{N} as a structural pattern
    and stops after the loop_threshold.
    """
    content = f"""
    <h2>Page {page_num}</h2>
    <p>This is dynamically generated page #{page_num}.</p>
    <p>Content: {'Lorem ipsum ' * 20}</p>
    <nav>
        <a href="/page/{max(page_num - 1, 1)}">← Previous</a> |
        <a href="/page/{page_num + 1}">Next →</a> |
        <a href="/page/{page_num + 2}">Skip →</a>
    </nav>
    """
    return render_template_string(LAYOUT, title=f"Page {page_num}", content=content)


@app.route("/products")
def products():
    """Another crawler loop pattern: product listing with many pages."""
    page = int(request.args.get("page", 1))
    content = "<h2>Products</h2><ul>"
    for i in range(10):
        pid = (page - 1) * 10 + i + 1
        content += f'<li><a href="/product/{pid}">Product #{pid}</a></li>'
    content += "</ul>"
    content += f'<a href="/products?page={page + 1}">Next Page →</a>'
    return render_template_string(LAYOUT, title="Products", content=content)


@app.route("/product/<int:product_id>")
def product_detail(product_id):
    """Individual product pages — another structural pattern for the crawler."""
    content = f"""
    <h2>Product #{product_id}</h2>
    <p>Price: ${random.randint(10, 999)}.99</p>
    <p>Description: {'High quality product ' * 5}</p>
    <a href="/product/{product_id + 1}">Next Product →</a>
    <a href="/products">Back to Products</a>
    """
    return render_template_string(LAYOUT, title=f"Product {product_id}", content=content)


# ═══════════════════════════════════════════════════════════
#  XXE — XML External Entity
# ═══════════════════════════════════════════════════════════

@app.route("/api/xml", methods=["GET", "POST"])
def xml_api():
    """❌ XXE: Parses XML input without disabling external entities."""
    if request.method == "GET":
        content = """
        <h2>XML API</h2>
        <p>POST XML data to this endpoint:</p>
        <pre>POST /api/xml
Content-Type: application/xml

&lt;request&gt;&lt;name&gt;test&lt;/name&gt;&lt;/request&gt;</pre>
        """
        return render_template_string(LAYOUT, title="XML API", content=content)

    import xml.etree.ElementTree as ET
    try:
        # ❌ VULNERABLE: Parsing XML without disabling external entities
        data = request.data.decode("utf-8")
        root = ET.fromstring(data)
        result = {"status": "parsed", "root_tag": root.tag}
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════
#  CORS MISCONFIGURATION
# ═══════════════════════════════════════════════════════════

@app.route("/api/data")
def api_data():
    """❌ CORS: Reflects any origin, allows credentials."""
    data = {"users": 4, "status": "active", "debug": True}
    resp = jsonify(data)
    # ❌ VULNERABLE: Wildcard origin with credentials
    origin = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# ═══════════════════════════════════════════════════════════
#  RATE LIMITER DEMO — slow endpoint
# ═══════════════════════════════════════════════════════════

@app.route("/slow")
def slow_endpoint():
    """Endpoint that responds slowly to trigger rate limiter adaptation."""
    delay = random.uniform(1.0, 3.0)
    time.sleep(delay)
    return jsonify({"status": "ok", "delay_ms": int(delay * 1000)})


@app.route("/flaky")
def flaky_endpoint():
    """Endpoint that randomly returns errors to trigger rate limiter."""
    if random.random() < 0.4:
        return jsonify({"error": "server overloaded"}), 503
    return jsonify({"status": "ok"})


# ═══════════════════════════════════════════════════════════
#  DIRECTORY LISTING — exposed /files/
# ═══════════════════════════════════════════════════════════

@app.route("/uploads/")
def uploads_directory():
    """❌ Directory listing enabled."""
    files_dir = Path(__file__).parent / "files"
    files = list(files_dir.glob("*")) if files_dir.exists() else []
    content = "<h1>Index of /uploads/</h1><hr>"
    content += '<a href="/">Parent Directory</a><br>'
    for f in files:
        content += f'<a href="/uploads/{f.name}">{f.name}</a> - {f.stat().st_size} bytes<br>'
    return content


# ═══════════════════════════════════════════════════════════
#  DANGEROUS HTTP METHODS
# ═══════════════════════════════════════════════════════════

@app.route("/api/resource", methods=["GET", "PUT", "DELETE", "OPTIONS", "TRACE"])
def dangerous_methods():
    """❌ Dangerous HTTP methods enabled (PUT, DELETE, TRACE)."""
    if request.method == "OPTIONS":
        resp = Response("")
        resp.headers["Allow"] = "GET, PUT, DELETE, TRACE, OPTIONS"
        return resp
    return jsonify({"method": request.method, "status": "accepted"})


# ═══════════════════════════════════════════════════════════
#  ADMIN PAGE — sensitive path
# ═══════════════════════════════════════════════════════════

@app.route("/admin")
def admin_page():
    """❌ Admin page accessible without authentication."""
    content = """
    <h2>Admin Panel</h2>
    <p>Welcome, Administrator!</p>
    <ul>
        <li>Total Users: 4</li>
        <li>Database: SQLite 3.39.0</li>
        <li>Debug Mode: ON</li>
    </ul>
    """
    return render_template_string(LAYOUT, title="Admin", content=content)


# ═══════════════════════════════════════════════════════════
#  SENSITIVE FILES — .env, robots.txt, etc.
# ═══════════════════════════════════════════════════════════

@app.route("/.env")
def dotenv():
    """❌ .env file exposed."""
    return Response(
        "DB_PASSWORD=admin123\nSECRET_KEY=mysecretkey\nAPI_KEY=sk-1234567890\n",
        mimetype="text/plain",
    )


@app.route("/robots.txt")
def robots():
    return Response(
        "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /.env\n",
        mimetype="text/plain",
    )


@app.route("/.git/config")
def git_config():
    """❌ Git config exposed."""
    return Response(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/user/secret-repo.git\n",
        mimetype="text/plain",
    )


@app.route("/backup.sql")
def backup_sql():
    """❌ Database backup exposed."""
    return Response(
        "-- MySQL dump\nCREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(50));\nINSERT INTO users VALUES (1, 'admin', 'admin123');\n",
        mimetype="text/plain",
    )


# ═══════════════════════════════════════════════════════════
#  STATIC ASSETS — for traffic store filtering demo
# ═══════════════════════════════════════════════════════════

@app.route("/static/style.css")
def static_css():
    return Response("body { font-family: Arial; }", mimetype="text/css")


@app.route("/static/app.js")
def static_js():
    return Response("console.log('loaded');", mimetype="application/javascript")


@app.route("/static/logo.png")
def static_png():
    # 1x1 transparent PNG
    import base64
    pixel = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    )
    return Response(pixel, mimetype="image/png")


@app.route("/favicon.ico")
def favicon():
    return Response(b"", mimetype="image/x-icon")


# ═══════════════════════════════════════════════════════════
#  FALSE POSITIVE BAIT — generic error pages
# ═══════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    """Generic 404 page that might trigger false SQLi detection."""
    return render_template_string("""
    <html>
    <head><title>404 Not Found</title></head>
    <body>
        <h1>Page Not Found</h1>
        <p>The page you requested was not found on this server.</p>
        <p>Error 404: The requested URL was not found.</p>
    </body>
    </html>
    """), 404


@app.errorhandler(500)
def server_error(e):
    return render_template_string("""
    <html>
    <head><title>Internal Server Error</title></head>
    <body>
        <h1>Internal Server Error</h1>
        <p>An unexpected error occurred. Sorry, something went wrong.</p>
    </body>
    </html>
    """), 500


# ═══════════════════════════════════════════════════════════
#  RUN SERVER
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  ⚠️  VULNERABLE TEST APPLICATION — DO NOT USE IN PRODUCTION")
    print("=" * 60)
    print(f"\n  Server running at: http://127.0.0.1:5001")
    print(f"  Database: {DB_PATH}")
    print(f"\n  Vulnerabilities included:")
    print(f"    • SQL Injection (GET + POST)")
    print(f"    • Reflected XSS")
    print(f"    • Stored XSS")
    print(f"    • Open Redirect")
    print(f"    • SSRF")
    print(f"    • Path Traversal")
    print(f"    • XXE")
    print(f"    • IDOR")
    print(f"    • Missing Security Headers")
    print(f"    • Insecure Cookies")
    print(f"    • CORS Misconfiguration")
    print(f"    • Information Disclosure")
    print(f"    • Directory Listing")
    print(f"    • Dangerous HTTP Methods")
    print(f"    • Sensitive File Exposure")
    print(f"    • Infinite Pagination (Crawler Loop)")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5001, debug=False)
