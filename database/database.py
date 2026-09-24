import sqlite3


DATABASE_PATH = "database/labsec.db"


def create_database():
    """
    Creates the LabSec SQLite database and required tables.
    """

    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT,
            state TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            FOREIGN KEY (target_id) REFERENCES targets(id)
        )
    """)

    connection.commit()
    connection.close()


def add_target(ip_address):
    """
    Adds a target to the database if it does not already exist.
    Returns the target ID.
    """

    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    cursor.execute(
        "INSERT OR IGNORE INTO targets (ip_address) VALUES (?)",
        (ip_address,)
    )

    connection.commit()

    cursor.execute(
        "SELECT id FROM targets WHERE ip_address = ?",
        (ip_address,)
    )

    target = cursor.fetchone()

    connection.close()

    if target is None:
        raise RuntimeError("Target could not be found in database.")

    return target[0]


def add_service(target_id, service_data):
    """
    Adds a discovered service to the database.
    """

    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO services (
            target_id,
            port,
            protocol,
            state,
            service,
            product,
            version
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        target_id,
        int(service_data["port"]),
        service_data["protocol"],
        service_data["state"],
        service_data["service"],
        service_data["product"],
        service_data["version"]
    ))

    connection.commit()
    connection.close()


if __name__ == "__main__":
    create_database()
    print("LabSec database created successfully.")
