from src.logger import SBSLogger

class SBSHoneypot:
    def __init__(self):
        self.logger = SBSLogger()
        self.safe_ports = {80, 443, 53, 123} 

    def process_packet(self, packet):
        src_ip = packet.src_addr
        dst_port = packet.dst_port
        
        if dst_port in self.safe_ports:
            return None

        payload_data = b""
        try:
            if packet.payload:
                payload_data = bytes(packet.payload)
        except AttributeError:
            pass

        payload_text = payload_data.decode('utf-8', errors='ignore').strip()
        payload_lower = payload_text.lower()

        # Daftar kata kunci perintah berbahaya yang jelas
        dangerous_cmds = [
            "cmd.exe", "powershell", "whoami", "wget", "curl", 
            "nc ", "bash -c", "/bin/sh", "python -c", "perl -e",
            "rm -rf", "del /f", "format c:", "reg add", "schtasks"
        ]

        is_attack = False
        category = None
        description = None

        # Deteksi port tinggi (>=49152) dengan payload berisi perintah berbahaya
        if dst_port >= 49152 and len(payload_text) > 0:
            # Hanya anggap TROJAN jika payload mengandung kata kunci perintah
            if any(cmd in payload_lower for cmd in dangerous_cmds):
                category = "TROJAN"
                description = f"🚨 TROJAN TERDETEKSI! Payload perintah shell berbahaya di Port Tinggi {dst_port}!"
                is_attack = True
            else:
                # Payload biner acak / tidak mengandung perintah -> abaikan
                return None

        # Deteksi port database/web (SQL Injection / XSS)
        elif dst_port in {8080, 8443, 1433, 3306, 5432, 27017}:
            if any(x in payload_lower for x in ["' or '1'='1", "<script>", "union select", "drop table", "select * from", "eval(", "exec("]):
                category = "MALWARE"
                description = f"⚠️ Percobaan injeksi SQL/XSS pada port database/web {dst_port}!"
                is_attack = True
            elif len(payload_text) > 0:
                category = "SUSPICIOUS"
                description = f"Permintaan tidak biasa pada port layanan {dst_port}."
                is_attack = True

        # Deteksi port remote & file sharing
        elif dst_port in {21, 22, 23}:
            if len(payload_text) > 0:
                category = "HACKER"
                description = f"Upaya pemindaian ilegal pada port remote akses ({dst_port})."
                is_attack = True
        elif dst_port in {135, 137, 139, 445}:
            category = "RANSOMWARE"
            description = "⚠️ BAHAYA! Aktivitas pemindaian SMB. Pola penyebaran virus Ransomware!"
            is_attack = True
        elif dst_port == 3389:
            category = "HACKER"
            description = "Upaya pembajakan atau pengintipan layar Windows Remote Desktop."
            is_attack = True
        elif dst_port == 5900:
            category = "VIRUS"
            description = "Upaya akses ilegal ke VNC Remote Control."
            is_attack = True

        if not is_attack:
            return None

        attack_detail = f"[{category}] Dari IP: {src_ip} mengetuk Port: {dst_port} -> Analisis: {description}"
        if payload_text:
            attack_detail += f" | Payload: {payload_text[:50]}"

        gui_log_msg = self.logger.format_alert(attack_detail)
        self.logger.write_to_file(category, f"IP: {src_ip} | Port: {dst_port} | Payload: {payload_text}")
        
        return gui_log_msg

    def process_system_info(self, info_message):
        gui_log_msg = self.logger.format_info(info_message)
        self.logger.write_to_file("INFO", info_message)
        return gui_log_msg