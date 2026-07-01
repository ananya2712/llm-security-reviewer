"""User database access (SYNTHETIC eval fixture — pre-fix, vulnerable)."""
import sqlite3


def connect():
    return sqlite3.connect("app.db")


def get_user(uid):
    conn = connect()
    cur = conn.cursor()
    q = "SELECT * FROM users WHERE id = " + str(uid)
    cur.execute(q)
    return cur.fetchone()
