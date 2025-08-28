import sqlite3

# Укажите путь к базе данных SQLite
DATABASE_PATH = "/root/cabinet/instance/users.db"

def add_column():
    # Подключение к базе данных
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    try:
        # SQL-запрос для добавления нового столбца
        cursor.execute("""
            ALTER TABLE user ADD COLUMN platform_id TEXT;
        """)
        conn.commit()
        print("Столбец 'platform_id' успешно добавлен в таблицу 'user'.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("Столбец 'platform_id' уже существует.")
        else:
            print(f"Ошибка при добавлении столбца: {e}")
    finally:
        # Закрытие подключения
        conn.close()

if __name__ == "__main__":
    add_column()
