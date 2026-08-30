import datetime
import os

class SBSLogger:
    def __init__(self, log_file_path="sbs_activity.log", max_size=1024*1024):  # 1 MB
        self.log_file_path = log_file_path
        self.max_size = max_size

    def _get_timestamp(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _rotate_if_needed(self):
        """Rotasi file log jika ukuran melebihi max_size"""
        if os.path.exists(self.log_file_path) and os.path.getsize(self.log_file_path) > self.max_size:
            # Pindahkan file ke .1, .2, dst.
            for i in range(4, 0, -1):
                src = f"{self.log_file_path}.{i-1}" if i > 1 else self.log_file_path
                dst = f"{self.log_file_path}.{i}"
                if os.path.exists(src):
                    if os.path.exists(dst):
                        os.remove(dst)
                    os.rename(src, dst)
            # Buat file baru kosong
            with open(self.log_file_path, "w", encoding="utf-8") as f:
                pass

    def format_info(self, message):
        return f"[{self._get_timestamp()}] [INFO] {message}"

    def format_alert(self, message):
        return f"[{self._get_timestamp()}] ⚠️ [ALERT] {message}"

    def write_to_file(self, level, message):
        """Menyimpan log ke dalam file text di harddisk dengan rotasi"""
        try:
            self._rotate_if_needed()
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(f"[{self._get_timestamp()}] [{level}] {message}\n")
        except Exception:
            pass  # Mengabaikan eror jika file log sedang dikunci oleh sistem
