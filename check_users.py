import sqlite3

DATABASE = 'database.db'

def print_users():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('SELECT id, username, email, role FROM users')
    users = cur.fetchall()
    for user in users:
        print(f"ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Role: {user[3]}")
    conn.close()

if __name__ == '__main__':
    print_users()
