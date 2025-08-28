import sqlite3

DATABASE = '/instance/orders.db'

def create_database():
    """Создает таблицу orders в базе данных."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL,
            phone_number TEXT,
            email TEXT,
            delivery_address TEXT,
            product_name TEXT,
            subscription_end_date DATETIME,
            platform_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print("База данных создана или уже существует.")

if __name__ == "__main__":
    create_database()
