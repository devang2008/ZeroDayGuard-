import sqlite3

conn = sqlite3.connect('database/ecommerce.db')
c = conn.cursor()

# Delete the 4 problematic products (iPhone, Canon, Kindle, Surface)
c.execute("DELETE FROM products WHERE name IN ('iPhone 15 Pro', 'Canon EOS R6 Mark II', 'Kindle Paperwhite', 'Microsoft Surface Pro 9')")
print('✅ Deleted 4 problematic products')

# Update ALL remaining products with realistic prices
c.execute("UPDATE products SET price = 199999.00 WHERE name = 'MacBook Pro 16'")
c.execute("UPDATE products SET price = 24999.00 WHERE name = 'Sony WH-1000XM5'")
c.execute("UPDATE products SET price = 59999.00 WHERE name = 'iPad Air M2'")
c.execute("UPDATE products SET price = 89999.00 WHERE name = 'Apple Watch Ultra 2'")
c.execute("UPDATE products SET price = 124999.00 WHERE name = 'Samsung Galaxy S24 Ultra'")
c.execute("UPDATE products SET price = 159999.00 WHERE name = 'Dell XPS 15'")
c.execute("UPDATE products SET price = 26900.00 WHERE name = 'AirPods Pro 2'")
c.execute("UPDATE products SET price = 54990.00 WHERE name = 'PlayStation 5'")
c.execute("UPDATE products SET price = 34999.00 WHERE name = 'Nintendo Switch OLED'")
c.execute("UPDATE products SET price = 34999.00 WHERE name = 'Bose QuietComfort Ultra'")
c.execute("UPDATE products SET price = 129999.00 WHERE name LIKE 'LG C3 OLED%'")
c.execute("UPDATE products SET price = 9999.00 WHERE name = 'Logitech MX Master 3S'")
c.execute("UPDATE products SET price = 44999.00 WHERE name = 'GoPro HERO12 Black'")
c.execute("UPDATE products SET price = 12999.00 WHERE name = 'Razer BlackWidow V4'")
c.execute("UPDATE products SET price = 19999.00 WHERE name = 'Samsung Galaxy Buds2 Pro'")
c.execute("UPDATE products SET price = 59999.00 WHERE name = 'DJI Mini 4 Pro'")

print('✅ Updated all product prices to realistic INR values')

conn.commit()

# Show the results
c.execute('SELECT id, name, price FROM products ORDER BY price')
rows = c.fetchall()
print('\n📦 Current products:')
for r in rows:
    print(f'{r[1]:30s} ₹{r[2]:,.2f}')

conn.close()
