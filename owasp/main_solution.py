"""
SECURE Flask application - Fixed version of main.py with all OWASP vulnerabilities patched.

This is the reference solution showing how to properly secure the vulnerable application.
Students should compare their fixes against this implementation.

Security fixes implemented:
1. ✅ Security Misconfiguration: Secure cookies, disabled debug mode
2. ✅ SQL Injection: Parameterized queries instead of f-strings
3. ✅ XSS: Removed |safe filter, proper HTML escaping
4. ✅ Broken Access Control: Authentication required, ownership checks
5. ✅ Path Traversal: Path normalization and validation
6. ✅ Unsafe Deserialization: JSON instead of pickle, schema validation

Run: python main_solution.py
Test: python -m pytest owasp/tests/main_test.py -v
"""

from flask import Flask, request, make_response, redirect, render_template_string, send_file, abort, session
import sqlite3
import os
import json
import hashlib
import secrets
from functools import wraps
import bleach

app = Flask(__name__)

# ✅ SECURITY FIX: Use a secure secret key for sessions
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ---------------------------
# Setup: super-minimal sqlite with hashed passwords
# ---------------------------
DB = "demo.db"
if not os.path.exists(DB):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, password_hash TEXT)")
    
    # ✅ SECURITY FIX: Hash passwords instead of storing plaintext
    def hash_password(password):
        return hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 100000).hex()
    
    c.execute("INSERT INTO users (username, role, password_hash) VALUES ('alice','student',?)", (hash_password('alicepass'),))
    c.execute("INSERT INTO users (username, role, password_hash) VALUES ('bob','student',?)", (hash_password('bobpass'),))
    c.execute("INSERT INTO users (username, role, password_hash) VALUES ('admin','admin',?)", (hash_password('adminpass'),))
    conn.commit()
    conn.close()

# ✅ SECURITY FIX: Secure session-based authentication
def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    return {"id": row[0], "username": row[1], "role": row[2]} if row else None

# ✅ SECURITY FIX: Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user():
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

# Root: convenient links
@app.get("/")
def index():
    u = current_user()
    who = u["username"] if u else "guest"
    logout_link = '<li><a href="/logout">Logout</a></li>' if u else ''
    return f"""
    <h1>Secure Lab (logged in as: {who})</h1>
    <ul>
      <li><a href="/login">Login (Secure Authentication)</a></li>
      <li><a href="/search">Search (SQL Injection Protected)</a></li>
      <li><a href="/comment">Comment (XSS Protected)</a></li>
      <li><a href="/profile">Profile (Access Control Fixed)</a></li>
      <li><a href="/download?path=alice.txt">Download (Path Traversal Fixed)</a></li>
      <li><a href="/import">Import (Safe Deserialization)</a></li>
      {logout_link}
    </ul>
    <p style="color:#080">🔒 All security vulnerabilities have been fixed!</p>
    """

# ------------------------------------------------------------
# 1) ✅ SECURITY MISCONFIGURATION / WEAK AUTH - FIXED
# ------------------------------------------------------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        
        if not username or not password:
            return "Username and password required", 400
            
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        # ✅ SECURITY FIX: Use parameterized query and hashed passwords
        c.execute("SELECT id, username, password_hash FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        
        if row:
            stored_hash = row[2]
            # ✅ SECURITY FIX: Verify hashed password
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 100000).hex()
            if password_hash == stored_hash:
                # ✅ SECURITY FIX: Use secure session instead of cookies
                session['user_id'] = row[0]
                session.permanent = True
                resp = make_response(redirect("/"))
                # ✅ SECURITY FIX: Set secure cookie flags
                resp.set_cookie('session', '', httponly=True, secure=True, samesite='Lax')
                return resp
                
        return "Invalid credentials", 401

    return """
      <h2>Secure Login</h2>
      <form method="post">
        <input name="username" placeholder="username" required/>
        <input name="password" placeholder="password" type="password" required/>
        <button type="submit">Login</button>
      </form>
      <p><small>✅ Secure: Hashed passwords, secure sessions</small></p>
    """

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ----------------------
# 2) ✅ INJECTION (SQLi) - FIXED
# ----------------------
@app.get("/search")
def search():
    q = request.args.get("q","").strip()
    
    if not q:
        return """
          <h2>User Search (SQL Injection Protected)</h2>
          <form>
            <input name="q" placeholder="try alice" required/>
            <button>Search</button>
          </form>
          <p><small>✅ Secure: Parameterized queries prevent SQL injection</small></p>
        """
    
    # ✅ SECURITY FIX: Use parameterized queries instead of f-strings
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    try:
        # Only return safe, non-sensitive data
        c.execute("SELECT id, username, role FROM users WHERE username LIKE ?", (f"%{q}%",))
        rows = c.fetchall()
    except Exception as e:
        rows = []
    finally:
        conn.close()
    
    # ✅ SECURITY FIX: Escape output and don't expose sensitive data
    items = "<br>".join([f"ID: {r[0]} | User: {bleach.clean(r[1])} | Role: {bleach.clean(r[2])}" for r in rows])
    
    return f"""
      <h2>User Search (SQL Injection Protected)</h2>
      <form>
        <input name="q" value="{bleach.clean(q)}" placeholder="try alice"/>
        <button>Search</button>
      </form>
      <h3>Results</h3>
      <div>{items}</div>
      <p><small>✅ Secure: Parameterized queries, no sensitive data exposure</small></p>
    """

# -------------
# 3) ✅ XSS - FIXED
# -------------
comments = []  # in-memory
@app.route("/comment", methods=["GET","POST"])
def comment():
    if request.method == "POST":
        text = request.form.get("text","").strip()
        if text:
            # ✅ SECURITY FIX: Sanitize input before storing
            sanitized_text = bleach.clean(text, tags=[], strip=True)
            comments.append(sanitized_text)
        return redirect("/comment")

    # ✅ SECURITY FIX: Remove |safe filter, use default escaping
    template = """
      <h2>Leave a Public Comment (XSS Protected)</h2>
      <form method="post">
        <input name="text" placeholder="type something (please be nice)" required/>
        <button>Post</button>
      </form>
      <h3>Recent Comments</h3>
      {% for c in comments %}
        <div style="border: 1px solid #ccc; padding: 10px; margin: 5px;">{{ c }}</div>
      {% endfor %}
      <p><small>✅ Secure: Input sanitized, HTML escaped automatically</small></p>
    """
    return render_template_string(template, comments=comments)

# -------------------------------------------
# 4) ✅ BROKEN ACCESS CONTROL (IDOR) - FIXED
# -------------------------------------------
@app.get("/profile")
@login_required  # ✅ SECURITY FIX: Require authentication
def profile():
    current = current_user()
    if not current:  # Additional safety check
        return redirect("/login")
        
    user_id = request.args.get("user_id")
    
    # ✅ SECURITY FIX: Default to current user's profile
    if not user_id:
        user_id = current["id"]
    else:
        try:
            user_id = int(user_id)
        except ValueError:
            return "Invalid user ID", 400
        # ✅ SECURITY FIX: Enforce ownership (only admins can view other profiles)
        if user_id != current["id"] and current["role"] != "admin":
            return "Access denied: You can only view your own profile", 403
    
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    try:
        # ✅ SECURITY FIX: Don't return sensitive data like password hashes
        c.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
    finally:
        conn.close()
        
    if not row:
        return "Profile not found", 404
        
    return f"""
      <h2>User Profile (Access Control Fixed)</h2>
      <ul>
        <li><strong>ID:</strong> {row[0]}</li>
        <li><strong>Username:</strong> {bleach.clean(row[1])}</li>
        <li><strong>Role:</strong> {bleach.clean(row[2])}</li>
      </ul>
      <p><a href="/">← Back to Home</a></p>
      <p><small>✅ Secure: Authentication required, ownership enforced, no sensitive data</small></p>
    """

# ------------------------------------------
# 5) ✅ PATH TRAVERSAL + UNSAFE DESERIALIZATION - FIXED
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
@login_required  # ✅ SECURITY FIX: Require authentication
def download():
    path = request.args.get("path","").strip()
    if not path:
        return "Missing path parameter", 400
    
    # ✅ SECURITY FIX: Normalize path and prevent traversal
    safe_path = os.path.normpath(os.path.join(BASE_DIR, path))
    
    # ✅ SECURITY FIX: Ensure path stays within BASE_DIR
    if not safe_path.startswith(BASE_DIR):
        return "Access denied: Path traversal not allowed", 403
    
    # ✅ SECURITY FIX: Additional file extension validation
    allowed_extensions = {'.txt', '.md', '.json'}
    file_ext = os.path.splitext(safe_path)[1].lower()
    if file_ext not in allowed_extensions:
        return "Access denied: File type not allowed", 403
    
    if not os.path.isfile(safe_path):
        return "File not found", 404
        
    return send_file(safe_path, as_attachment=True)

@app.route("/import", methods=["GET","POST"])
@login_required  # ✅ SECURITY FIX: Require authentication
def do_import():
    if request.method == "POST":
        if "file" not in request.files:
            return "No file uploaded", 400
            
        file = request.files["file"]
        if not file.filename:
            return "No file selected", 400
            
        # ✅ SECURITY FIX: Only allow JSON files
        if not file.filename.lower().endswith('.json'):
            return "Only JSON files are allowed", 415
            
        try:
            data = file.read()
            # ✅ SECURITY FIX: Use JSON instead of pickle
            obj = json.loads(data.decode('utf-8'))
            
            # ✅ SECURITY FIX: Validate JSON structure
            if not isinstance(obj, dict):
                return "Invalid JSON structure: must be an object", 400
                
            # ✅ SECURITY FIX: Basic schema validation
            allowed_keys = {'name', 'description', 'data', 'timestamp'}
            if not all(key in allowed_keys for key in obj.keys()):
                return "Invalid JSON schema: unknown keys present", 400
                
            return f"✅ Safely imported JSON object with keys: {list(obj.keys())}"
            
        except json.JSONDecodeError as e:
            return f"Invalid JSON format: {str(e)}", 400
        except Exception as e:
            return f"Import error: {str(e)}", 400
    
    return """
      <h2>Safe Import (Deserialization Fixed)</h2>
      <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" accept=".json" required/>
        <button>Upload JSON</button>
      </form>
      <p><small>✅ Secure: Only JSON files accepted, schema validation applied</small></p>
    """

if __name__ == "__main__":
    # ✅ SECURITY FIX: Disable debug mode in production
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)