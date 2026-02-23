#!/usr/bin/env python3
import os
import sqlite3
from werkzeug.security import generate_password_hash

DB = os.environ.get("DATABASE_PATH", "/var/lib/logic-lab/logiclab.db")

def main():
    con = sqlite3.connect(DB)
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS orgs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    )
    """)

    # These assumes your app's schema already exists for users/services.
    # If not, create them in your app migration/bootstrap logic.
    for table in ["services", "users", "orgs"]:
        try:
            cur.execute(f"DELETE FROM {table}")
        except sqlite3.OperationalError:
            pass

    try:
        cur.execute("DELETE FROM sqlite_sequence WHERE name IN ('services','users','orgs')")
    except sqlite3.OperationalError:
        pass

    cur.execute("INSERT INTO orgs (name) VALUES (?)", ("Core Admin",))
    admin_org_id = cur.lastrowid

    cur.execute(
        "INSERT INTO users (username, password_hash, is_admin, org_id) VALUES (?, ?, 1, ?)",
        ("admin", generate_password_hash("ChangeMe123!"), admin_org_id),
    )

    con.commit()
    con.close()
    print("Demo DB reset complete. Admin: admin / ChangeMe123! (change immediately)")

if __name__ == "__main__":
    main()
