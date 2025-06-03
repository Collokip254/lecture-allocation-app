import sqlite3

conn = sqlite3.connect('lecturers.db')
c = conn.cursor()
c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ('admin', 'admin'))
conn.commit()
conn.close()
print("Admin added successfully!")