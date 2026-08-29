import re
from src.logger import SBSLogger

class SBSHoneypot:
    def __init__(self):
        self.logger = SBSLogger()
        self.safe_ports = {80, 443, 53, 123}  # port yang dianggap aman dan tidak perlu dianalisis

        # Kata kunci perintah berbahaya yang jelas (case-insensitive)
        self.dangerous_cmds = [
            "cmd.exe", "powershell", "whoami", "wget", "curl",
            "nc ", "bash -c", "/bin/sh", "python -c", "perl -e",
            "rm -rf", "del /f", "format c:", "reg add", "schtasks"
        ]

        # Kata kunci untuk SQL injection / XSS
        self.sql_patterns = [
            "' or '1'='1", "<script>", "union select",
            "drop table", "select * from", "eval(", "exec("
        ]

    def process_packet(self, packet):
        src_ip = packet.src_addr
        dst_port = packet.dst_port

        if dst_port in self.safe_ports:
            return None

        # Ambil payload (jika ada)
        payload_data = b""
        try:
            if packet.payload:
                payload_data = bytes(packet.payload)
        except AttributeError:
            pass

        # Batasi ukuran payload yang akan dianalisis untuk mencegah beban berlebih
        if len(payload_data) > 4096:
            return None

        payload_text = payload_data.decode('utf-8', errors='ignore').strip()
        payload_lower = payload_text.lower()

        is_attack = False
        category = None
        description = None

        # Deteksi pada port tinggi (>=49152): hanya jika payload mengandung kata kunci berbahaya
        if dst_port >= 49152:
            if len(payload_data) > 0:
                # Periksa apakah payload mengandung kata kunci perintah
                if any(cmd in payload_lower for cmd in self.dangerous_cmds):
                    category = "TROJAN"
                    description = f"🚨 TROJAN TERDETEKSI! Payload perintah shell berbahaya di Port Tinggi {dst_port}!"
                    is_attack = True
            # Jika tidak mengandung kata kunci, jangan log (mengurangi false positive)

        # Deteksi pada port layanan web/database (SQL injection / XSS)
        elif dst_port in {8080, 8443, 1433, 3306, 5432, 27017}:
            if any(x in payload_lower for x in self.sql_patterns):
                category = "MALWARE"
                description = f"⚠️ Percobaan injeksi SQL/XSS pada port database/web {dst_port}!"
                is_attack = True
            elif len(payload_text) > 0:
                category = "SUSPICIOUS"
                description = f"Permintaan tidak biasa pada port layanan {dst_port}."
                is_attack = True

        # Port remote & file sharing
        elif dst_port in {21, 22, 23}:
            if len(payload_text) > 0:
                category = "HACKER"
                description = f"Upaya pemindaian ilegal pada port remote akses ({dst_port})."
                is_attack = True
        elif dst_port in {135, 137, 139, 445}:
            # Hanya log jika ada payload (meskipun SMB, kita anggap mencurigakan)
            if len(payload_data) > 0:
                category = "RANSOMWARE"
                description = "⚠️ BAHAYA! Aktivitas pemindaian SMB. Pola penyebaran virus Ransomware!"
                is_attack = True
            # Jika tidak ada payload, mungkin hanya koneksi SYN, tidak perlu log
        elif dst_port == 3389:
            # RDP biasanya tidak membawa payload pada percobaan koneksi awal
            # Tapi kita log jika ada payload
            if len(payload_data) > 0:
                category = "HACKER"
                description = "Upaya pembajakan atau pengintipan layar Windows Remote Desktop."
                is_attack = True
        elif dst_port == 5900:
            if len(payload_data) > 0:
                category = "VIRUS"
                description = "Upaya akses ilegal ke VNC Remote Control."
                is_attack = True

        if not is_attack:
            return None

        attack_detail = f"[{category}] Dari IP: {src_ip} mengetuk Port: {dst_port} -> Analisis: {description}"
        if payload_text:
            # Potong payload agar log tidak terlalu panjang
            attack_detail += f" | Payload: {payload_text[:100]}"

        gui_log_msg = self.logger.format_alert(attack_detail)
        self.logger.write_to_file(category, f"IP: {src_ip} | Port: {dst_port} | Payload: {payload_text[:200]}")
        return gui_log_msg

    def process_system_info(self, info_message):
        gui_log_msg = self.logger.format_info(info_message)
        self.logger.write_to_file("INFO", info_message)
        return gui_log_msg
