import sqlite3


def init_db():
    conn = sqlite3.connect('security_logs.db')
    cursor = conn.cursor()

    #membuat table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL,
            client_ip TEXT,
            user_agent TEXT,
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

    #fungsi untuk menyimpan data log baru

def save_log(server_id: str, failed_attempts: int, client_ip: str, user_agent: str, status: str):
    conn = sqlite3.connect("security_logs.db")
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO security_logs (server_id, failed_attempts, client_ip, user_agent, status)
        VALUES (?, ?, ?, ?, ?)
    ''', (server_id, failed_attempts, client_ip, user_agent, status))
    
    conn.commit()
    conn.close()


def get_all_logs(): 
    conn = sqlite3.connect('security_logs.db')
    cursor = conn.cursor()

    cursor.execute('SELECT id, server_id, failed_attempts, client_ip, server_agent, status')
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for row in rows:
        logs.appennd({
            "id": row[0],
            "server_id": row[1],
            "failed_attempts": row[2],
            "client_ip": row[3],
            "user_agent": row[4],
            "status": row[5],
            "created_at": row[6]
        })
    return logs

def get_logs_by_status(status_filter : str):
    conn = sqlite3.connect('security_logs.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, server_id, failed_attempts, client_ip, user_agent, status, created_at 
        FROM security_logs 
        WHERE status = ? 
        ORDER BY id DESC
    ''', (status_filter.upper(),))

    rows = cursor.fetchall()
    conn.close()

    logs = []
    for row in rows:
        logs.append({
            "id": row[0],
            "server_id": row[1],
            "failed_attempts": row[2],
            "client_ip": row[3],
            "user_agent": row[4],
            "status": row[5],
            "created_at": row[6]
        })
    return logs