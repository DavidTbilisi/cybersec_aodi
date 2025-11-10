# tests/main_test.py
"""
Pytest suite to validate that the 5 OWASP demo vulnerabilities were fixed.

ALL TESTS SHOULD FAIL INITIALLY - this is expected!
The main.py file contains intentional security vulnerabilities that students must fix.

Run from the project root directory:
  pip install flask pytest
  python -m pytest owasp/tests/main_test.py -v

This suite uses Flask's test_client (no external network needed).

Expected behavior:
- BEFORE fixes: All 5 tests FAIL (vulnerabilities detected)
- AFTER fixes: All 5 tests PASS (vulnerabilities resolved)
"""

import os
import sqlite3
import io
import pickle
import pytest
from importlib import reload

# Import app from student's file. Assumes main.py defines `app`.
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import main as student_app_module

# reload in case tests are run repeatedly while editing the app
reload(student_app_module)
app = student_app_module.app

DB_PATH = os.path.abspath(getattr(student_app_module, "DB", "demo.db"))
BASE_DIR = os.path.abspath(getattr(student_app_module, "BASE_DIR", "notes"))

@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    Create a test client that uses a temporary working directory.
    Copy demo.db and notes/ to tmp_path so tests don't mutate student's original files.
    """
    # prepare tmp environment
    orig_cwd = os.getcwd()
    tmpdir = tmp_path / "lab"
    tmpdir.mkdir()
    # copy DB if it exists
    if os.path.exists(DB_PATH):
        import shutil
        shutil.copy(DB_PATH, tmpdir / "demo.db")
    # copy notes directory if exists
    if os.path.isdir(BASE_DIR):
        import shutil
        shutil.copytree(BASE_DIR, tmpdir / "notes")
    # change cwd to tmpdir for the test
    os.chdir(str(tmpdir))
    # monkeypatch path in module to point to copied DB/notes
    monkeypatch.setattr(student_app_module, "DB", str(tmpdir / "demo.db"), raising=False)
    monkeypatch.setattr(student_app_module, "BASE_DIR", str(tmpdir / "notes"), raising=False)
    # reload to pick up patched DB/BASE_DIR (if any code reads them at import-time)
    reload(student_app_module)
    test_client = student_app_module.app.test_client()
    yield test_client
    # restore cwd
    os.chdir(orig_cwd)


def table_exists(db_path, table_name="users"):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table_name,))
    exists = cur.fetchone() is not None
    conn.close()
    return exists

def count_users(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM users;")
        n = cur.fetchone()[0]
    except sqlite3.OperationalError:
        n = None
    conn.close()
    return n

# ------------------
# 1) SQLi protection
# ------------------
def test_search_does_not_drop_users_and_handles_malicious_q(client):
    """
    Send a malicious q that would exploit string-formatted SQL if present.
    Expect: search returns 200; users table still exists and count intact.
    Also test that SQLi injection doesn't expose unauthorized data.
    """
    # First, test a direct SQL injection that should fail in vulnerable code
    evil_union = "' UNION SELECT id, username, password FROM users --"
    r = client.get(f"/search?q={evil_union}")
    body = r.get_data(as_text=True)
    
    # Vulnerable code will show password data in search results
    assert "alicepass" not in body and "bobpass" not in body and "adminpass" not in body, \
        "❌ SQL INJECTION VULNERABILITY: Passwords exposed in search results! Fix: Use parameterized queries instead of f-strings in SQL."
    
    # Test table drop attack
    evil_drop = "%'; DROP TABLE users; --"
    r2 = client.get(f"/search?q={evil_drop}")
    assert r2.status_code == 200, "Search endpoint should respond 200 (no SQL crash)."

    # DB must still contain users table and at least 1 user
    assert table_exists("demo.db"), "users table was dropped — SQLi not handled."
    n = count_users("demo.db")
    assert isinstance(n, int) and n >= 1, "users table is missing or empty after search."


# --------------
# 2) XSS fixed
# --------------
def test_comments_are_escaped_and_no_raw_script_in_response(client):
    """
    Post a comment containing a <script> tag. When listing comments, the raw <script>
    should NOT appear in the returned HTML (should be escaped or removed).
    """
    payload = {"text": '<script>alert("xss")</script>'}
    # submit comment
    post = client.post("/comment", data=payload, follow_redirects=True)
    assert post.status_code in (200, 302), "Posting a comment should succeed."
    # get the page
    r = client.get("/comment")
    body = r.get_data(as_text=True)
    # raw <script> must not be present
    assert "<script>" not in body and "</script>" not in body, \
        "❌ XSS VULNERABILITY: Raw <script> tags present in HTML! Fix: Remove |safe filter from templates or sanitize with Bleach."
    # the content may be encoded like &lt;script&gt;... or removed; that's okay


# -----------------------------------
# 3) Broken Access Control (IDOR) fixed
# -----------------------------------
def test_profile_requires_auth_and_no_password_exposure(client):
    """
    Accessing /profile without login should not leak user password or show profile.
    The fixed app should require auth (401/403/redirect) or at least not show the 'password' field.
    """
    r = client.get("/profile?user_id=1", follow_redirects=False)
    # acceptable secure behaviors: redirect to login (302), 401, 403, or 404
    assert r.status_code in (302, 401, 403, 404), \
        f"❌ BROKEN ACCESS CONTROL (IDOR): Profile accessible without authentication (got {r.status_code})! Fix: Require login and check user ownership."

    # If app chooses to return content (e.g., 200), ensure it doesn't include 'password'
    if r.status_code == 200:
        body = r.get_data(as_text=True)
        assert "password" not in body.lower(), "Profile leaks password field — sensitive data exposure."


# -----------------------
# 4) Path traversal blocked
# -----------------------
def test_download_prevents_path_traversal_and_serves_allowed_file(client):
    """
    Attempts to download ../main.py should be blocked (404/400/403). Allowed filename should work.
    """
    # Create the main.py file that we'll try to access via path traversal
    with open("main.py", "w", encoding="utf-8") as f:
        f.write("# This is the main application file - should not be downloadable")
    
    # traversal attempt - try to access main.py which should be blocked
    r = client.get("/download?path=../main.py")
    
    # If vulnerable, this will return 200 and serve the file
    if r.status_code == 200:
        content = r.get_data(as_text=True)
        if "This is the main application file" in content:
            assert False, "❌ PATH TRAVERSAL VULNERABILITY: ../main.py was served! Fix: Normalize paths and check they stay within BASE_DIR."
    
    assert r.status_code in (400, 403, 404), f"Path traversal not blocked (got status {r.status_code})"

    # allowed file (seeded alice.txt in notes/)
    # make sure alice.txt exists in the test notes directory
    notes_dir = os.path.join(os.getcwd(), "notes")
    os.makedirs(notes_dir, exist_ok=True)
    with open(os.path.join(notes_dir, "alice.txt"), "w", encoding="utf-8") as f:
        f.write("Alice private note")
    r2 = client.get("/download?path=alice.txt")
    assert r2.status_code == 200, f"Allowed download failed (status {r2.status_code})."
    content = r2.get_data()
    assert b"Alice private note" in content, "Downloaded file content mismatch."


# ---------------------------------------
# 5) Unsafe deserialization (pickle) fixed
# ---------------------------------------
def test_import_rejects_pickle_and_allows_safe_json_or_rejects_untrusted_serialization(client):
    """
    Send a pickle payload — the secure app should reject it (400/415/403).
    If the fixed design accepts a JSON-only import, the pickle should still be rejected.
    """
    # craft a safe pickle payload (for test only)
    test_obj = {"ok": True}
    pickled = pickle.dumps(test_obj)
    data = {
        "file": (io.BytesIO(pickled), "payload.pkl")
    }
    r = client.post("/import", data=data, content_type="multipart/form-data")
    assert r.status_code in (400, 403, 415), \
        f"❌ UNSAFE DESERIALIZATION: Pickle files accepted (status {r.status_code})! Fix: Replace pickle with JSON and validate schema."

    # Optionally check that JSON import path works if implemented: POST a .json file
    json_bytes = b'{"ok": true}'
    data2 = {"file": (io.BytesIO(json_bytes), "payload.json")}
    r2 = client.post("/import", data=data2, content_type="multipart/form-data")
    # Acceptable secure behaviors:
    # - Accept JSON (200) if safe parsing is implemented
    # - Or reject other file types (400/415)
    assert r2.status_code in (200, 400, 415, 403), "Unexpected response for JSON import."
