import sqlite3

conn = sqlite3.connect('database/ecommerce.db')
cursor = conn.cursor()

print("=" * 60)
print("DATABASE STRUCTURE - VulnShop E-Commerce")
print("=" * 60)

# Show all tables
print("\n📊 Tables:")
tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
for table in tables:
    print(f"  ✓ {table[0]}")

# Show users
print("\n👥 Users Table:")
print("-" * 60)
users = cursor.execute("SELECT id, username, email, role FROM users").fetchall()
for user in users:
    print(f"  ID: {user[0]} | Username: {user[1]} | Email: {user[2]} | Role: {user[3]}")

# Show products
print("\n🛍️  Products Table:")
print("-" * 60)
products = cursor.execute("SELECT id, name, price, stock FROM products").fetchall()
for product in products:
    print(f"  ID: {product[0]} | {product[1]} | ${product[2]} | Stock: {product[3]}")

# Show comments
print("\n💬 Comments Table:")
print("-" * 60)
comments = cursor.execute("SELECT id, product_id, user_id, comment FROM comments LIMIT 10").fetchall()
if comments:
    for comment in comments:
        print(f"  ID: {comment[0]} | Product: {comment[1]} | User: {comment[2]} | Comment: {comment[3][:50]}...")
else:
    print("  (No comments yet)")

# Show orders
print("\n📦 Orders Table:")
print("-" * 60)
orders = cursor.execute("SELECT id, user_id, total, status FROM orders LIMIT 10").fetchall()
if orders:
    for order in orders:
        print(f"  ID: {order[0]} | User: {order[1]} | Total: ${order[2]} | Status: {order[3]}")
else:
    print("  (No orders yet)")

print("\n" + "=" * 60)
print("Database Location: database/ecommerce.db")
print("=" * 60)

conn.close()
