# Demo E-Commerce Application

**INTENTIONALLY VULNERABLE APPLICATION FOR SECURITY TESTING**

⚠️ **WARNING: This application contains intentional security vulnerabilities for educational purposes only!**

## Features
- User authentication (login/register)
- Product catalog
- Shopping cart
- User profile management
- Admin panel

## Intentional Vulnerabilities Included:
1. **SQL Injection** - Login bypass, product search
2. **XSS (Cross-Site Scripting)** - Comment section, search results
3. **Command Injection** - Image processing
4. **Path Traversal** - File download
5. **Hard-coded Credentials** - Database connection
6. **Weak Cryptography** - MD5 password hashing
7. **CSRF** - Profile update without tokens
8. **Insecure Deserialization** - Session handling
9. **Buffer Overflow** - C extension module
10. **NULL Pointer Dereference** - C utilities

## Tech Stack
- **Backend**: Python Flask + C extensions
- **Frontend**: HTML, CSS, JavaScript
- **Database**: SQLite

## Setup
```bash
cd demoproject
pip install -r requirements.txt
python backend/app.py
```

Open: http://localhost:3000

## Test Credentials
- Admin: admin / admin123
- User: user / password

## Vulnerability Testing Examples

### SQL Injection
```
Username: admin' OR '1'='1
Password: anything
```

### XSS
```
Comment: <script>alert('XSS')</script>
```

### Path Traversal
```
Download: ../../etc/passwd
```

## DO NOT USE IN PRODUCTION!
This is for educational security testing only.
