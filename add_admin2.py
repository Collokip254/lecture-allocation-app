import sqlite3

# Connect to the database
conn = sqlite3.connect('lecturers.db')
c = conn.cursor()

# Insert admin credentials (replace with your desired usernames and passwords)
admins = [
    ('admin1', 'password123'),
    ('admin2', 'securepass456'),
    ('admin3', 'admin789')
]

for username, password in admins:
    c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", (username, password))

# Commit the changes and close the connection
conn.commit()
conn.close()

print("Admin accounts added successfully!")