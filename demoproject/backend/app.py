"""
E-Commerce Application Backend (INTENTIONALLY VULNERABLE)
WARNING: Contains multiple security vulnerabilities for testing purposes
"""

from flask import Flask, request, jsonify, send_file, send_from_directory, session
from flask_cors import CORS
import sqlite3
import hashlib
import os
import json
import pickle
import subprocess
from datetime import datetime

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

# VULNERABILITY: Hard-coded secret key (CWE-798)
app.secret_key = "super_secret_key_12345"

# VULNERABILITY: Hard-coded database credentials (CWE-798)
DB_PATH = 'database/ecommerce.db'
ADMIN_PASSWORD = "admin123"
API_KEY = "sk_live_abc123xyz789"

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Serve the main page"""
    return send_from_directory('../frontend', 'index.html')

def init_database():
    """Initialize database with sample data"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            stock INTEGER,
            image TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            user_id INTEGER,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            total REAL,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # VULNERABILITY: Weak cryptography - MD5 for passwords (CWE-327)
    admin_pass = hashlib.md5("admin123".encode()).hexdigest()
    user_pass = hashlib.md5("password".encode()).hexdigest()
    
    # Insert default users
    cursor.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            ("admin", admin_pass, "admin@example.com", "admin")
        )
        cursor.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            ("user", user_pass, "user@example.com", "user")
        )
    
    # Insert sample products
    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        products = [
            ("MacBook Pro 16", "Apple M3 Max chip, 36GB RAM, 1TB SSD - Professional laptop for creators", 3499.99, 12, "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=500"),
            ("iPhone 15 Pro", "A17 Pro chip, 256GB, Titanium design with advanced camera system", 1199.99, 35, "https://images.unsplash.com/photo-1592286927505-b0e2d7e8b9c0?w=500"),
            ("Sony WH-1000XM5", "Industry-leading noise canceling wireless headphones, 30hr battery", 399.99, 48, "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=500"),
            ("iPad Air M2", "10.9-inch Liquid Retina display, 128GB, Space Gray", 599.99, 28, "https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=500"),
            ("Apple Watch Ultra 2", "GPS + Cellular, 49mm Titanium case, Rugged outdoor smartwatch", 799.99, 22, "https://images.unsplash.com/photo-1579586337278-3befd40fd17a?w=500"),
            ("Samsung Galaxy S24 Ultra", "Snapdragon 8 Gen 3, 12GB RAM, 512GB, AI-powered smartphone", 1299.99, 18, "https://images.unsplash.com/photo-1610945415295-d9bbf067e59c?w=500"),
            ("Dell XPS 15", "Intel Core i9, 32GB RAM, RTX 4060, 15.6\" OLED display", 2299.99, 8, "https://images.unsplash.com/photo-1593642632823-8f785ba67e45?w=500"),
            ("AirPods Pro 2", "Active Noise Cancellation, Adaptive Audio, USB-C charging", 249.99, 65, "https://images.unsplash.com/photo-1606841837239-c5a1a4a07af7?w=500"),
            ("PlayStation 5", "1TB SSD, 4K gaming console with DualSense controller", 499.99, 15, "https://images.unsplash.com/photo-1606813907291-d86efa9b94db?w=500"),
            ("Nintendo Switch OLED", "7-inch OLED screen, 64GB, Neon Red/Blue joy-cons", 349.99, 42, "https://images.unsplash.com/photo-1578303512597-81e6cc155b3e?w=500"),
            ("Bose QuietComfort Ultra", "Premium wireless earbuds with spatial audio and ANC", 299.99, 38, "https://images.unsplash.com/photo-1590658268037-6bf12165a8df?w=500"),
            ("Canon EOS R6 Mark II", "24.2MP Full-Frame mirrorless camera, 4K 60fps video", 2499.99, 6, "https://images.unsplash.com/photo-1606980707580-f2d47f23ca4d?w=500"),
            ("LG C3 OLED TV 55\"", "4K Smart TV, α9 AI Processor, HDMI 2.1, Gaming features", 1799.99, 10, "https://images.unsplash.com/photo-1593359677879-a4bb92f829d1?w=500"),
            ("Logitech MX Master 3S", "Ergonomic wireless mouse, 8K DPI, Quiet clicks, Multi-device", 99.99, 88, "https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=500"),
            ("Kindle Paperwhite", "6.8\" display, adjustable warm light, 16GB, waterproof e-reader", 149.99, 52, "https://images.unsplash.com/photo-1592168292764-e67b531bfdc6?w=500"),
            ("GoPro HERO12 Black", "5.3K60 video, HyperSmooth 6.0, HDR, waterproof action camera", 399.99, 24, "https://images.unsplash.com/photo-1519120944692-1a8d8cfc107f?w=500")
        ]
        cursor.executemany(
            "INSERT INTO products (name, description, price, stock, image) VALUES (?, ?, ?, ?, ?)",
            products
        )
    
    conn.commit()
    conn.close()

# VULNERABILITY: SQL Injection in login (CWE-89)
@app.route('/api/login', methods=['POST'])
def login():
    """Login endpoint with SQL injection vulnerability"""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABILITY: Direct string concatenation in SQL query
    conn = get_db_connection()
    
    # Weak password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # SQL INJECTION VULNERABILITY!
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password_hash}'"
    print(f"Executing query: {query}")  # Debug - exposes query
    
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # VULNERABILITY: Insecure session management
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'role': user['role']
                }
            })
        else:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    except Exception as e:
        # VULNERABILITY: Information disclosure through error messages
        return jsonify({'success': False, 'error': str(e)}), 500

# VULNERABILITY: SQL Injection in registration (CWE-89)
@app.route('/api/register', methods=['POST'])
def register():
    """Register new user with SQL injection"""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    email = data.get('email', '')
    
    # VULNERABILITY: No input validation
    # VULNERABILITY: Weak password hashing (MD5)
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    conn = get_db_connection()
    
    # SQL INJECTION VULNERABILITY!
    query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password_hash}', '{email}')"
    
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'User registered successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# VULNERABILITY: Insecure Direct Object Reference (IDOR) - CWE-639
@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_data(user_id):
    """Get user data without authorization check"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # No authorization check - anyone can access any user's data
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        })
    return jsonify({'error': 'User not found'}), 404

# VULNERABILITY: Server-Side Request Forgery (SSRF) - CWE-918
@app.route('/api/fetch-image', methods=['GET'])
def fetch_image():
    """Fetch image from URL without validation"""
    url = request.args.get('url', '')
    
    # No URL validation - can access internal resources
    import urllib.request
    try:
        response = urllib.request.urlopen(url, timeout=5)
        data = response.read()
        return data, 200, {'Content-Type': 'image/jpeg'}
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# VULNERABILITY: XML External Entity (XXE) - CWE-611
@app.route('/api/import-xml', methods=['POST'])
def import_xml():
    """Import product data from XML without disabling external entities"""
    xml_data = request.data
    
    import xml.etree.ElementTree as ET
    try:
        # Vulnerable to XXE attacks
        root = ET.fromstring(xml_data)
        products = []
        for product in root.findall('product'):
            products.append({
                'name': product.find('name').text,
                'price': product.find('price').text
            })
        return jsonify({'success': True, 'products': products})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# VULNERABILITY: Directory Listing / Path Disclosure - CWE-548
@app.route('/api/files', methods=['GET'])
def list_files():
    """List files in directory without restriction"""
    directory = request.args.get('dir', '.')
    
    try:
        files = os.listdir(directory)
        file_list = []
        for f in files:
            full_path = os.path.join(directory, f)
            file_list.append({
                'name': f,
                'path': full_path,
                'is_dir': os.path.isdir(full_path)
            })
        return jsonify({'files': file_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# VULNERABILITY: Unvalidated Redirect - CWE-601
@app.route('/api/redirect', methods=['GET'])
def redirect_url():
    """Redirect to URL without validation"""
    from flask import redirect
    url = request.args.get('url', '/')
    # No validation - can redirect to malicious sites
    return redirect(url)

# VULNERABILITY: SQL Injection in product search (CWE-89)
@app.route('/api/products/search', methods=['GET'])
def search_products():
    """Search products with SQL injection vulnerability"""
    search_term = request.args.get('q', '')
    
    conn = get_db_connection()
    
    # SQL INJECTION VULNERABILITY!
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%' OR description LIKE '%{search_term}%'"
    print(f"Search query: {query}")
    
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        products = cursor.fetchall()
        conn.close()
        
        return jsonify([dict(p) for p in products])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/products', methods=['GET'])
def get_products():
    """Get all products"""
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    
    return jsonify([dict(p) for p in products])

# VULNERABILITY: XSS in comments (CWE-79)
@app.route('/api/comments', methods=['POST'])
def add_comment():
    """Add comment with XSS vulnerability"""
    data = request.get_json()
    product_id = data.get('product_id')
    user_id = session.get('user_id', 1)
    comment = data.get('comment', '')
    
    # VULNERABILITY: No sanitization of comment (XSS)
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO comments (product_id, user_id, comment) VALUES (?, ?, ?)',
        (product_id, user_id, comment)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/comments/<int:product_id>', methods=['GET'])
def get_comments(product_id):
    """Get comments for product"""
    conn = get_db_connection()
    comments = conn.execute(
        'SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE c.product_id = ?',
        (product_id,)
    ).fetchall()
    conn.close()
    
    # VULNERABILITY: Returns unsanitized comments (XSS)
    return jsonify([dict(c) for c in comments])

# VULNERABILITY: Path Traversal (CWE-22)
@app.route('/api/download', methods=['GET'])
def download_file():
    """Download file with path traversal vulnerability"""
    filename = request.args.get('file', '')
    
    # VULNERABILITY: No path validation!
    filepath = os.path.join('uploads', filename)
    
    try:
        return send_file(filepath)
    except Exception as e:
        return jsonify({'error': str(e)}), 404

# VULNERABILITY: Command Injection (CWE-78)
@app.route('/api/process-image', methods=['POST'])
def process_image():
    """Process image with command injection vulnerability"""
    data = request.get_json()
    image_name = data.get('image', '')
    
    # VULNERABILITY: Command injection through unsanitized input
    command = f"convert uploads/{image_name} -resize 100x100 uploads/thumb_{image_name}"
    
    try:
        # DANGEROUS: Using shell=True with user input
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return jsonify({'success': True, 'output': result.stdout})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# VULNERABILITY: CSRF - No token validation (CWE-352)
@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    """Update user profile without CSRF protection"""
    data = request.get_json()
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    email = data.get('email', '')
    
    # VULNERABILITY: No CSRF token validation
    conn = get_db_connection()
    conn.execute('UPDATE users SET email = ? WHERE id = ?', (email, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# VULNERABILITY: Insecure Deserialization (CWE-502)
@app.route('/api/save-cart', methods=['POST'])
def save_cart():
    """Save shopping cart using insecure pickle"""
    data = request.get_json()
    cart = data.get('cart', [])
    user_id = session.get('user_id', 1)
    
    # VULNERABILITY: Using pickle for serialization
    cart_data = pickle.dumps(cart)
    
    # Save to file
    with open(f'carts/cart_{user_id}.pkl', 'wb') as f:
        f.write(cart_data)
    
    return jsonify({'success': True})

@app.route('/api/load-cart', methods=['GET'])
def load_cart():
    """Load shopping cart using insecure pickle"""
    user_id = session.get('user_id', 1)
    
    try:
        with open(f'carts/cart_{user_id}.pkl', 'rb') as f:
            # VULNERABILITY: Deserializing untrusted data
            cart = pickle.loads(f.read())
        
        return jsonify({'cart': cart})
    except:
        return jsonify({'cart': []})

# VULNERABILITY: Information disclosure
@app.route('/api/debug', methods=['GET'])
def debug_info():
    """Debug endpoint exposing sensitive information"""
    return jsonify({
        'database': DB_PATH,
        'secret_key': app.secret_key,
        'api_key': API_KEY,
        'admin_password': ADMIN_PASSWORD,
        'session': dict(session),
        'environment': dict(os.environ)
    })

if __name__ == '__main__':
    # Initialize database
    os.makedirs('database', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('carts', exist_ok=True)
    
    init_database()
    
    print("=" * 60)
    print("🔓 VULNERABLE E-COMMERCE APPLICATION STARTED")
    print("=" * 60)
    print("⚠️  WARNING: This application contains intentional vulnerabilities!")
    print("📍 Server: http://localhost:3000")
    print("\nTest credentials:")
    print("  Admin: admin / admin123")
    print("  User:  user / password")
    print("\nVulnerabilities included:")
    print("  ✗ SQL Injection (login, search, register)")
    print("  ✗ XSS (comments)")
    print("  ✗ Command Injection (image processing)")
    print("  ✗ Path Traversal (file download)")
    print("  ✗ Hard-coded credentials")
    print("  ✗ Weak crypto (MD5)")
    print("  ✗ CSRF (profile update)")
    print("  ✗ Insecure deserialization (pickle)")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=3000)
