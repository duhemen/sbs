import datetime
import os

class SBSLogger:
    def __init__(self, log_file_path="sbs_activity.log"):
        self.log_file_path = log_file_path

    def _get_timestamp(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def format_info(self, message):
        """Format untuk informasi sistem biasa"""
        return f"[{self._get_timestamp()}] [INFO] {message}"

    def format_alert(self, message):
        """Format khusus untuk serangan / deteksi honeypot"""
        return f"[{self._get_timestamp()}] ⚠️ [ALERT] {message}"

    def write_to_file(self, level, message):
        """Menyimpan log ke dalam file text di harddisk"""
        try:
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(f"[{self._get_timestamp()}] [{level}] {message}\n")
        except Exception:
            pass  # Mengabaikan eror jika file log sedang dikunci oleh sistem