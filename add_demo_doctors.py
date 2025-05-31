import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = 'database.db'

def add_demo_doctors():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    doctors = [
        ('Dr Smith - Dermatologist', 'drsmith@example.com', 'password123'),
        ('Dr John - Endocrinologist', 'drjones@example.com', 'password123'),
        ('Dr Lee - Cardiologist' , 'drlee@example.com', 'password123'),
    ]

    for username, email, password in doctors:
        hashed_password = generate_password_hash(password)
        try:
            cur.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                        (username, email, hashed_password, 'doctor'))
            print(f"Added doctor: {username}")
        except sqlite3.IntegrityError:
            print(f"Doctor {username} or email {email} already exists.")

    conn.commit()
    conn.close()

if __name__ == '__main__':
    add_demo_doctors()
