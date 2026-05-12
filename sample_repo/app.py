import sqlite3

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE" # Intentional hardcoded secret

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Intentional SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'") 
    return cursor.fetchall()