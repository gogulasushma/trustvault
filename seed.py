import secrets
import sqlite3

from werkzeug.security import generate_password_hash

conn = sqlite3.connect("trustvault.db")
for username, role in [("admin1", "admin"), ("owner1", "owner"), ("viewer1", "viewer")]:
    password = secrets.token_urlsafe(12)
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        print(f"{username} ({role}) password: {password}")
    except sqlite3.IntegrityError:
        print(f"{username} already exists, skipped")
conn.commit()
conn.close()