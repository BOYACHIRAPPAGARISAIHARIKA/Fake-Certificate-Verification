# --- 2. DATABASE ARCHITECTURE ---
def init_db():
    conn = sqlite3.connect('vericert_enterprise.db')
    c = conn.cursor()
    
    # Create certificates table with all required columns
    c.execute('''CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    hash TEXT,
                    reg_date TIMESTAMP,
                    meta_info TEXT
                )''')
    
    # Create logs table
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT,
                    user TEXT,
                    timestamp TIMESTAMP
                )''')
    
    # --- DATABASE MIGRATION: Handle old schema ---
    # Check if 'date' column exists (old schema) and rename/migrate
    try:
        c.execute("SELECT date FROM certificates LIMIT 1")
    except sqlite3.OperationalError:
        # Column doesn't exist, check if we need to add reg_date
        try:
            c.execute("SELECT reg_date FROM certificates LIMIT 1")
        except sqlite3.OperationalError:
            # reg_date doesn't exist either, add it
            c.execute("ALTER TABLE certificates ADD COLUMN reg_date TIMESTAMP")
    
    # Also check for 'meta_info' column
    try:
        c.execute("SELECT meta_info FROM certificates LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE certificates ADD COLUMN meta_info TEXT")
    
    conn.commit()
    conn.close()