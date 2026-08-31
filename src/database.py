# src/database.py
import sqlite3
import datetime
import os

class SBSDatabase:
    def __init__(self, db_path="sbs_forensics.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Buat tabel detections jika belum ada
        c.execute('''CREATE TABLE IF NOT EXISTS detections
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      timestamp TEXT,
                      src_ip TEXT,
                      dst_port INTEGER,
                      category TEXT,
                      payload TEXT,
                      rekomendasi TEXT,
                      country TEXT,
                      city TEXT,
                      lat REAL,
                      lon REAL)''')
        
        # Migrasi: tambahkan kolom dst_ip jika belum ada
        c.execute("PRAGMA table_info(detections)")
        columns = [row[1] for row in c.fetchall()]
        if "dst_ip" not in columns:
            c.execute("ALTER TABLE detections ADD COLUMN dst_ip TEXT")
        
        # Buat tabel activity_log jika belum ada
        c.execute('''CREATE TABLE IF NOT EXISTS activity_log
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      timestamp TEXT,
                      src_ip TEXT,
                      dst_ip TEXT,
                      dst_port INTEGER,
                      category TEXT,
                      activity TEXT)''')
        
        conn.commit()
        conn.close()

    def insert_detection(self, timestamp, src_ip, dst_ip, dst_port, category, payload, rekomendasi):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO detections 
                     (timestamp, src_ip, dst_ip, dst_port, category, payload, rekomendasi)
                     VALUES (?,?,?,?,?,?,?)''',
                  (timestamp, src_ip, dst_ip, dst_port, category, payload, rekomendasi))
        conn.commit()
        conn.close()

    def update_geo_info(self, src_ip, country, city, lat, lon):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''UPDATE detections 
                     SET country = ?, city = ?, lat = ?, lon = ?
                     WHERE src_ip = ? AND (country IS NULL OR country = '')''',
                  (country, city, lat, lon, src_ip))
        conn.commit()
        conn.close()

    def get_all_detections(self, limit=100):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''SELECT id, timestamp, src_ip, dst_ip, dst_port, category, payload, rekomendasi,
                            country, city, lat, lon
                     FROM detections ORDER BY id DESC LIMIT ?''', (limit,))
        rows = c.fetchall()
        conn.close()
        return rows

    def get_detections_by_ip(self, src_ip):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''SELECT timestamp, src_ip, dst_ip, dst_port, category, payload, rekomendasi
                     FROM detections WHERE src_ip = ? ORDER BY id DESC''', (src_ip,))
        rows = c.fetchall()
        conn.close()
        return rows

    def log_activity(self, timestamp, src_ip, dst_ip, dst_port, category, activity):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO activity_log 
                     (timestamp, src_ip, dst_ip, dst_port, category, activity)
                     VALUES (?,?,?,?,?,?)''',
                  (timestamp, src_ip, dst_ip, dst_port, category, activity))
        conn.commit()
        conn.close()

    def get_activity_log(self, limit=100):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''SELECT timestamp, src_ip, dst_ip, dst_port, category, activity
                     FROM activity_log ORDER BY id DESC LIMIT ?''', (limit,))
        rows = c.fetchall()
        conn.close()
        return rows