"""
Flask demo of 5 OWASP-style vulns for students to secure.
Run:  pip install flask sqlite-utils
      python app.py
"""

from flask import Flask, request, make_response, redirect, render_template_string, send_file, abort
import sqlite3, os, pickle, io

app = Flask(__name__)

# ---------------------------
# Setup: super-minimal sqlite
# ---------------------------
DB = "demo.db"
if not os.path.exists(DB):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, password TEXT)")
    c.execute("INSERT INTO users (username, role, password) VALUES ('alice','student','alicepass')")
    c.execute("INSERT INTO users (username, role, password) VALUES ('bob','student','bobpass')")
    c.execute("INSERT INTO users (username, role, password) VALUES ('admin','admin','adminpass')")
    conn.commit()
    conn.close()

# Simple "session" using a cookie (also intentionally weak)
def current_user():
    username = request.cookies.get("user")
    if not username:
        return None
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    return {"id": row[0], "username": row[1], "role": row[2]} if row else None

# Root: convenient links
@app.get("/")
def index():
    u = current_user()
    who = u["username"] if u else "guest"
    return f"""
    <h1>Vuln Lab (logged in as: {who})</h1>
    <ul>
      <li><a href="/login">Login (Security Misconfiguration / Weak Auth)</a></li>
      <li><a href="/search">Search (Injection / SQLi)</a></li>
      <li><a href="/comment">Comment (XSS)</a></li>
      <li><a href="/profile?user_id=1">Profile (Broken Access Control / IDOR)</a></li>
      <li><a href="/download?path=notes/alice.txt">Download (Path Traversal)</a></li>
      <li><a href="/import">Import (Unsafe Deserialization)</a></li>
    </ul>
    <p style="color:#c00">Everything here is intentionally unsafe. Patch it.</p>
    """

# ------------------------------------------------------------
# 1) SECURITY MISCONFIGURATION / WEAK AUTH (also cookies flags)
# ------------------------------------------------------------
@app.route("/login", methods=["GET","POST"])
def login():
    # VULNERABLE: plaintext passwords, no rate limiting, no CSRF, no secure cookie flags
    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        # Here we use a safe param query (to keep focus elsewhere), but overall auth is weak.
        c.execute("SELECT username FROM users WHERE username=? AND password=?", (username, password))
        row = c.fetchone()
        conn.close()
        if row:
            resp = make_response(redirect("/"))
            # VULNERABLE: no HttpOnly/Secure/SameSite, cookie stores identity directly
            resp.set_cookie("user", username)  # TODO: use signed session, HttpOnly, Secure, SameSite
            return resp
        return "Invalid creds", 401

    return """
      <h2>Login</h2>
      <form method="post">
        <input name="username" placeholder="user"/>
        <input name="password" placeholder="pass" type="password"/>
        <button type="submit">Login</button>
      </form>
    """

# ----------------------
# 2) INJECTION (SQLi)
# ----------------------
@app.get("/search")
def search():
    q = request.args.get("q","")
    # VULNERABLE: unsafe string formatting into SQL
    sql = f"SELECT id, username, role FROM users WHERE username LIKE '%{q}%'"
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    try:
        rows = c.execute(sql).fetchall()
    except Exception as e:
        rows = [("SQL error", str(e), "")]
    conn.close()
    items = "<br>".join([f"{r[0]} | {r[1]} | {r[2]}" for r in rows])
    return f"""
      <h2>User search</h2>
      <form>
        <input name="q" value="{q}" placeholder="try alice"/>
        <button>Go</button>
      </form>
      <h3>Results</h3>
      <pre>{items}</pre>
      <p style="color:#c00"># VULNERABLE: string concatenation in SQL</p>
    """

# -------------
# 3) XSS
# -------------
comments = []  # in-memory
@app.route("/comment", methods=["GET","POST"])
def comment():
    if request.method == "POST":
        text = request.form.get("text","")
        # VULNERABLE: store user input and render unsanitized
        comments.append(text)
        return redirect("/comment")

    # VULNERABLE: render_template_string with unescaped content
    template = """
      <h2>Leave a public comment</h2>
      <form method="post">
        <input name="text" placeholder="type something (please be nice)"/>
        <button>Post</button>
      </form>
      <h3>Recent</h3>
      {% for c in comments %}
        <div>{{ c|safe }}</div> <!-- VULNERABLE: |safe disables escaping -->
      {% endfor %}
      <p style="color:#c00"># VULNERABLE: stored XSS</p>
    """
    return render_template_string(template, comments=comments)

# -------------------------------------------
# 4) BROKEN ACCESS CONTROL (IDOR)
# -------------------------------------------
@app.get("/profile")
def profile():
    # VULNERABLE: anyone can read any profile by id; no ownership checks, no auth required
    user_id = request.args.get("user_id")
    if not user_id:
        return "Missing user_id", 400
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    try:
        row = c.execute("SELECT id, username, role, password FROM users WHERE id=?", (user_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return "Not found", 404
    return f"""
      <h2>Profile</h2>
      <ul>
        <li>id: {row[0]}</li>
        <li>username: {row[1]}</li>
        <li>role: {row[2]}</li>
        <li>password: {row[3]}</li> <!-- VULNERABLE: sensitive data exposure -->
      </ul>
      <p style="color:#c00"># VULNERABLE: IDOR + sensitive data exposure</p>
    """

# ------------------------------------------
# 5) PATH TRAVERSAL  +  UNSAFE DESERIALIZATION
# ------------------------------------------
BASE_DIR = os.path.abspath("notes")
os.makedirs(BASE_DIR, exist_ok=True)
# Seed files
for name, text in [("alice.txt","Alice private note"), ("bob.txt","Bob private note")]:
    p = os.path.join(BASE_DIR, name)
    if not os.path.exists(p):
        with open(p,"w",encoding="utf-8") as f:
            f.write(text)

@app.get("/download")
def download():
    # VULNERABLE: accepts raw path param; allows ../ traversal
    path = request.args.get("path","")
    full = os.path.join(BASE_DIR, path)  # no normalization / allowlist
    if not os.path.isfile(full):
        return "Not found", 404
    return send_file(full, as_attachment=True)
    # TODO: normalize path, enforce allowlist, and check per-user authorization

@app.route("/import", methods=["GET","POST"])
def do_import():
    # VULNERABLE: pickle.load on untrusted input -> RCE risk
    if request.method == "POST":
        if "file" not in request.files:
            return "No file", 400
        data = request.files["file"].read()
        try:
            obj = pickle.loads(data)  # VULNERABLE
        except Exception as e:
            return f"Error: {e}", 400
        return f"Imported object: {repr(obj)}"
    return """
      <h2>Unsafe import</h2>
      <form method="post" enctype="multipart/form-data">
        <input type="file" name="file"/>
        <button>Upload</button>
      </form>
      <p style="color:#c00"># VULNERABLE: unsafe deserialization (pickle)</p>
    """

if __name__ == "__main__":
    # VULNERABLE: debug=True leaks internals, enables interactive console on crashes
    app.run(host="0.0.0.0", port=5000, debug=True)
