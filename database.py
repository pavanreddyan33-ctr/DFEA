import sqlite3

def create_database():

    conn = sqlite3.connect("forensics.db")

    cursor = conn.cursor()

    # Evidence table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            stored_file TEXT,
            file_hash TEXT,
            file_size INTEGER,
            upload_date TEXT
        )
    """)

    # Chain of Custody table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS custody (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER,
            action TEXT,
            person TEXT,
            timestamp TEXT
        )
    """)

    conn.commit()

    conn.close()

    print("Database created successfully!")


if __name__ == "__main__":
    create_database()