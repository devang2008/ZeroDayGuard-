import sqlite3

conn = sqlite3.connect('backend/database/ecommerce.db')
c = conn.cursor()

c.execute("UPDATE products SET image = 'https://picsum.photos/seed/iphone15pro/500/500' WHERE id = 2")
c.execute("UPDATE products SET image = 'https://picsum.photos/seed/canonr6mark2/500/500' WHERE id = 12")
c.execute("UPDATE products SET image = 'https://picsum.photos/seed/kindlepaperwhite/500/500' WHERE id = 15")
c.execute("UPDATE products SET image = 'https://picsum.photos/seed/surfacepro9/500/500' WHERE id = 17")

conn.commit()
print('✅ 4 product images updated!')
conn.close()
