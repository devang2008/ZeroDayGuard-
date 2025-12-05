import sqlite3
import hashlib
import os

# Make sure we're using the correct database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'backend', 'database', 'ecommerce.db')
print(f"Database path: {DB_PATH}")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Create tables first
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

# Insert default users
admin_pass = hashlib.md5("admin123".encode()).hexdigest()
user_pass = hashlib.md5("password".encode()).hexdigest()

cursor.execute("DELETE FROM users")
cursor.execute(
    "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
    ("admin", admin_pass, "admin@example.com", "admin")
)
cursor.execute(
    "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
    ("user", user_pass, "user@example.com", "user")
)

# Delete old products
cursor.execute("DELETE FROM products")

# Insert new products with real images
products = [
    ("MacBook Pro 16", "Apple M3 Max chip, 36GB RAM, 1TB SSD - Professional laptop for creators", 2499.99, 12, "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=500"),
    ("iPhone 15 Pro", "A17 Pro chip, 256GB, Titanium design with advanced camera system", 1199.99, 35, "https://images.unsplash.com/photo-1592286927505-b0e2d7e8b9c0?w=500"),
    ("Sony WH-1000XM5", "Industry-leading noise canceling wireless headphones, 30hr battery", 399.99, 48, "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=500"),
    ("iPad Air M2", "10.9-inch Liquid Retina display, 128GB, Space Gray", 599.99, 28, "https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=500"),
    ("Apple Watch Ultra 2", "GPS + Cellular, 49mm Titanium case, Rugged outdoor smartwatch", 799.99, 22, "https://images.unsplash.com/photo-1579586337278-3befd40fd17a?w=500"),
    ("Samsung Galaxy S24 Ultra", "Snapdragon 8 Gen 3, 12GB RAM, 512GB, AI-powered smartphone", 1299.99, 18, "https://images.unsplash.com/photo-1610945415295-d9bbf067e59c?w=500"),
    ("Dell XPS 15", "Intel Core i9, 32GB RAM, RTX 4060, 15.6\" OLED display", 2199.99, 8, "https://images.unsplash.com/photo-1593642632823-8f785ba67e45?w=500"),
    ("AirPods Pro 2", "Active Noise Cancellation, Adaptive Audio, USB-C charging", 249.99, 65, "https://images.unsplash.com/photo-1606841837239-c5a1a4a07af7?w=500"),
    ("PlayStation 5", "1TB SSD, 4K gaming console with DualSense controller", 499.99, 15, "https://images.unsplash.com/photo-1606813907291-d86efa9b94db?w=500"),
    ("Nintendo Switch OLED", "7-inch OLED screen, 64GB, Neon Red/Blue joy-cons", 349.99, 42, "https://images.unsplash.com/photo-1578303512597-81e6cc155b3e?w=500"),
    ("Bose QuietComfort Ultra", "Premium wireless earbuds with spatial audio and ANC", 299.99, 38, "https://images.unsplash.com/photo-1590658268037-6bf12165a8df?w=500"),
    ("Canon EOS R6 Mark II", "24.2MP Full-Frame mirrorless camera, 4K 60fps video", 2499.99, 6, "https://images.unsplash.com/photo-1606980707580-f2d47f23ca4d?w=500"),
    ("LG C3 OLED TV 55\"", "4K Smart TV, α9 AI Processor, HDMI 2.1, Gaming features", 1799.99, 10, "https://images.unsplash.com/photo-1593359677879-a4bb92f829d1?w=500"),
    ("Logitech MX Master 3S", "Ergonomic wireless mouse, 8K DPI, Quiet clicks, Multi-device", 99.99, 88, "https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=500"),
    ("Kindle Paperwhite", "6.8\" display, adjustable warm light, 16GB, waterproof e-reader", 149.99, 52, "https://images.unsplash.com/photo-1592168292764-e67b531bfdc6?w=500"),
    ("GoPro HERO12 Black", "5.3K60 video, HyperSmooth 6.0, HDR, waterproof action camera", 399.99, 24, "https://images.unsplash.com/photo-1519120944692-1a8d8cfc107f?w=500"),
    ("Microsoft Surface Pro 9", "Intel i7, 16GB RAM, 512GB SSD, 13\" touchscreen tablet", 1599.99, 14, "https://images.unsplash.com/photo-1585790050230-5dd28404f28c?w=500"),
    ("Razer BlackWidow V4", "Mechanical gaming keyboard, RGB, Green switches, programmable", 179.99, 31, "https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=500"),
    ("Samsung Galaxy Buds2 Pro", "Intelligent ANC, 360 audio, Hi-Fi sound wireless earbuds", 229.99, 45, "https://images.unsplash.com/photo-1606220945770-b5b6c2c55bf1?w=500"),
    ("DJI Mini 4 Pro", "4K/60fps HDR, 34min flight time, omnidirectional obstacle sensing", 759.99, 9, "https://images.unsplash.com/photo-1473968512647-3e447244af8f?w=500")
]

cursor.executemany(
    "INSERT INTO products (name, description, price, stock, image) VALUES (?, ?, ?, ?, ?)",
    products
)

conn.commit()
conn.close()

print("✅ Products updated successfully!")
print(f"📦 {len(products)} products with real images added to database")
