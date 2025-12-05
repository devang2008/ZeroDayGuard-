import sqlite3

DB_PATH = 'backend/database/ecommerce.db'
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Update only the 4 broken images
updates = [
    (2, "https://picsum.photos/seed/iphone15/500/500"),
    (12, "https://picsum.photos/seed/canonr6/500/500"),
    (15, "https://picsum.photos/seed/kindlepaper/500/500"),
    (17, "https://picsum.photos/seed/surfacepro/500/500")
]

for product_id, new_image in updates:
    cursor.execute("UPDATE products SET image = ? WHERE id = ?", (new_image, product_id))
    print(f"✓ Updated product {product_id}")

# Set correct prices in INR
price_updates = [
    (1, 207499.00),   # MacBook Pro 16
    (2, 99599.00),    # iPhone 15 Pro
    (3, 33199.00),    # Sony WH-1000XM5
    (4, 49799.00),    # iPad Air M2
    (5, 66399.00),    # Apple Watch Ultra 2
    (6, 107899.00),   # Samsung Galaxy S24 Ultra
    (7, 182599.00),   # Dell XPS 15
    (8, 20749.00),    # AirPods Pro 2
    (9, 41499.00),    # PlayStation 5
    (10, 29049.00),   # Nintendo Switch OLED
    (11, 24899.00),   # Bose QuietComfort Ultra
    (12, 207499.00),  # Canon EOS R6 Mark II
    (13, 149399.00),  # LG C3 OLED TV 55"
    (14, 8299.00),    # Logitech MX Master 3S
    (15, 12449.00),   # Kindle Paperwhite
    (16, 33199.00),   # GoPro HERO12 Black
    (17, 132799.00),  # Microsoft Surface Pro 9
    (18, 14939.00),   # Razer BlackWidow V4
    (19, 19089.00),   # Samsung Galaxy Buds2 Pro
    (20, 63079.00)    # DJI Mini 4 Pro
]

for product_id, price_inr in price_updates:
    cursor.execute("UPDATE products SET price = ? WHERE id = ?", (price_inr, product_id))

print(f"\n✓ Updated {len(price_updates)} product prices to INR")

conn.commit()
conn.close()
print("\n✅ Images fixed and prices set to INR!")
