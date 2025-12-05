import sqlite3

conn = sqlite3.connect('database/ecommerce.db')
c = conn.cursor()

c.execute('SELECT COUNT(*) FROM products')
print(f'\nTotal products: {c.fetchone()[0]}')

c.execute('SELECT id, name, price FROM products ORDER BY id')
rows = c.fetchall()

print('\nAll products:')
for r in rows:
    print(f'{r[0]:2d}. {r[1]:30s} ₹{r[2]:,.2f}')

conn.close()
