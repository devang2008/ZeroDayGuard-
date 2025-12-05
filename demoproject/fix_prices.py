import sqlite3

conn = sqlite3.connect('database/ecommerce.db')
cursor = conn.cursor()

# Update all product prices to Indian Rupees (realistic market prices)
price_updates = [
    ("MacBook Pro 16", 289999),           # ₹2,89,999
    ("iPhone 15 Pro", 134900),            # ₹1,34,900
    ("Sony WH-1000XM5", 29990),           # ₹29,990
    ("iPad Air M2", 59900),               # ₹59,900
    ("Apple Watch Ultra 2", 89900),       # ₹89,900
    ("Samsung Galaxy S24 Ultra", 129999), # ₹1,29,999
    ("Dell XPS 15", 199990),              # ₹1,99,990
    ("AirPods Pro 2", 26900),             # ₹26,900
    ("PlayStation 5", 54990),             # ₹54,990
    ("Nintendo Switch OLED", 34999),      # ₹34,999
    ("Bose QuietComfort Ultra", 26900),   # ₹26,900
    ("Canon EOS R6 Mark II", 249990),     # ₹2,49,990
    ("LG C3 OLED TV 55\"", 149990),       # ₹1,49,990
    ("Logitech MX Master 3S", 9995),      # ₹9,995
    ("Kindle Paperwhite", 14999),         # ₹14,999
    ("GoPro HERO12 Black", 44990),        # ₹44,990
]

for name, price in price_updates:
    cursor.execute("UPDATE products SET price = ? WHERE name = ?", (price, name))
    print(f"✅ Updated {name}: ₹{price:,}")

conn.commit()
conn.close()

print("\n💰 All prices updated to Indian Rupees successfully!")
