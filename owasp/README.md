




# OWASP Security Checklist

A comprehensive security checklist for students to secure their web applications against common vulnerabilities.

## Installation

Create and activate a virtual environment:
```bash
python -m venv venv
# source venv/bin/activate  # On Linux/Mac
# venv\Scripts\activate     # On Windows
```

Install the required packages:
```bash
pip install -r owasp/requirements.txt
```

Run the Flask application:
```bash

python owasp/main.py
```

Run the tests to verify security measures:
```bash
 # Test vulnerable version
rm -f demo.db
python -m pytest owasp/tests/main_test.py -v
```

## 🧪 Testing & Solution

### Testing Your Fixes
- **Expected initially**: All 5 tests FAIL (vulnerabilities detected)
- **After fixing**: All 5 tests PASS (vulnerabilities resolved)

### Files Overview
- `main.py` - Vulnerable application (fix the security issues here)
- `main_solution.py` - Reference implementation with all fixes
- `tests/main_test.py` - Security test suite
- `test_solution.py` - Script to test the solution

### Test the Solution
```bash
python owasp/test_solution.py
```

---


## 🔐 Security Misconfiguration / Weak Authentication

- [ ] **Disable debug mode in production**
  - Set `debug=False` in production environment
  
- [ ] **Implement proper session management**
  - Use Flask-Login (or equivalent) with proper sessions
  - Set cookies with `HttpOnly`, `Secure`, `SameSite=Lax/Strict`
  
- [ ] **Secure password handling**
  - Hash passwords with Argon2/bcrypt (using `passlib`)
  - Never store plaintext passwords
  
- [ ] **Add security middleware**
  - Implement rate limiting (`flask-limiter`)
  - Add CSRF protection (`Flask-WTF` or `flask-wtf.csrf`)

## 💉 Injection (SQL Injection)

- [ ] **Use parameterized queries**
  - Replace f-strings in SQL with parameterized queries
  - Example: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
  
- [ ] **Input validation and normalization**
  - Validate/normalize all user inputs
  - Consider allowlists for fields, limits, and pagination
  
- [ ] **Use ORM with bound parameters**
  - Consider using SQLAlchemy with bound params
  - Example: `User.query.filter(User.id == user_id).first()`

## 🕸️ Cross-Site Scripting (XSS)

- [ ] **Remove unsafe template filters**
  - Remove `|safe` from templates, rely on default autoescaping
  - Or sanitize with Bleach for rich text content
  
- [ ] **Implement output encoding**
  - Output-encode all user content
  - Consider adding Content-Security-Policy headers
  
- [ ] **Safe content rendering**
  - Prefer Markdown → sanitized HTML rendering
  - Use libraries like `bleach` or `markdown` with safe configurations

## 🚪 Broken Access Control (IDOR)

- [ ] **Require authentication**
  - Require authentication on sensitive routes like `/profile`
  
- [ ] **Enforce object ownership**
  - Implement authorization checks: `if user.id != requested_id and not is_admin: deny`
  - Verify user permissions before allowing access to resources
  
- [ ] **Data minimization**
  - Don't return sensitive data (e.g., password hashes)
  - Apply proper data minimization principles

## 📂 Path Traversal & Unsafe Deserialization

- [ ] **Secure path handling**
  ```python
  safe = os.path.normpath(os.path.join(BASE_DIR, path))
  if not safe.startswith(BASE_DIR):
      raise SecurityError("Invalid path")
  ```
  
- [ ] **File access controls**
  - Enforce per-user file ownership/allowlist
  - Don't use filenames as keys for sensitive operations
  
- [ ] **Safe serialization**
  - Replace `pickle` with safe formats like JSON
  - Validate data schema with `pydantic` or `jsonschema`

---

## 📋 Quick Security Review Checklist

Use this checklist to verify your application's security:

- [ ] Debug mode disabled in production
- [ ] Secure session management implemented
- [ ] Password hashing in place
- [ ] Rate limiting and CSRF protection active
- [ ] SQL injection prevention measures
- [ ] XSS protection implemented
- [ ] Access control properly enforced
- [ ] Path traversal protections in place
- [ ] Safe deserialization practices used