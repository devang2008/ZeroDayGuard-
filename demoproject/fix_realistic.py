import sqlite3

conn = sqlite3.connect('backend/database/ecommerce.db')
c = conn.cursor()

# Delete the 4 problematic products
c.execute("DELETE FROM products WHERE id IN (2, 12, 15, 17)")
print('✅ Deleted 4 problematic products')

# Update all prices to realistic Indian values
realistic_prices = [
    (1, 199999.00),   # MacBook Pro 16
    (3, 24999.00),    # Sony WH-1000XM5
    (4, 59999.00),    # iPad Air M2
    (5, 89999.00),    # Apple Watch Ultra 2
    (6, 124999.00),   # Samsung Galaxy S24 Ultra
    (7, 159999.00),   # Dell XPS 15
    (8, 26900.00),    # AirPods Pro 2
    (9, 54990.00),    # PlayStation 5
    (10, 34999.00),   # Nintendo Switch OLED
    (11, 34999.00),   # Bose QuietComfort Ultra
    (13, 129999.00),  # LG C3 OLED TV 55"
    (14, 9999.00),    # Logitech MX Master 3S
    (16, 44999.00),   # GoPro HERO12 Black
    (18, 12999.00),   # Razer BlackWidow V4
    (19, 19999.00),   # Samsung Galaxy Buds2 Pro
    (20, 59999.00)    # DJI Mini 4 Pro
]

for product_id, price in realistic_prices:
    c.execute("UPDATE products SET price = ? WHERE id = ?", (price, product_id))

print(f'✅ Updated {len(realistic_prices)} product prices to realistic INR values')

conn.commit()
conn.close()
