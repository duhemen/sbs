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
        """
        Memproses paket jaringan dan mengembalikan pesan log jika terdeteksi ancaman.
        """
        if getattr(packet, 'tcp', None):
            return self._process_tcp(packet)
        elif getattr(packet, 'udp', None):
            return self._process_udp(packet)
        return None

    def _process_tcp(self, packet):
        src_ip = packet.src_addr
        dst_port = packet.dst_port
        tcp_header = packet.tcp  # objek TCPHeader
        syn = tcp_header.syn
        ack = tcp_header.ack
        payload_data = b""

        try:
            if packet.payload:
                payload_data = bytes(packet.payload)
        except AttributeError:
            pass

        # Batasi ukuran payload untuk analisis
        if len(payload_data) > 4096:
            return None

        payload_text = payload_data.decode('utf-8', errors='ignore').strip()
        payload_lower = payload_text.lower()

        # 1. Deteksi port scanning (SYN tanpa ACK ke port yang tidak aman)
        if syn and not ack and dst_port not in self.safe_ports:
            category = "SUSPICIOUS"
            description = f"Pemindaian port (SYN) ke Port {dst_port} dari IP {src_ip}."
            return self._format_alert(category, src_ip, dst_port, description, payload_text)

        # 2. Deteksi pada port layanan web/database (SQL injection / XSS)
        if dst_port in {8080, 8443, 1433, 3306, 5432, 27017}:
            if any(x in payload_lower for x in self.sql_patterns):
                category = "MALWARE"
                description = f"Percobaan injeksi SQL/XSS pada port database/web {dst_port}!"
                return self._format_alert(category, src_ip, dst_port, description, payload_text)
            elif len(payload_text) > 0:
                category = "SUSPICIOUS"
                description = f"Permintaan tidak biasa pada port layanan {dst_port}."
                return self._format_alert(category, src_ip, dst_port, description, payload_text)

        # 3. Port remote & file sharing
        if dst_port in {21, 22, 23}:
            if len(payload_text) > 0 or (syn and not ack):
                category = "HACKER"
                description = f"Upaya akses ilegal pada port remote {dst_port}."
                return self._format_alert(category, src_ip, dst_port, description, payload_text)

        if dst_port in {135, 137, 139, 445}:
            # Log jika ada payload atau SYN scan
            if len(payload_data) > 0 or (syn and not ack):
                category = "RANSOMWARE"
                description = "Aktivitas mencurigakan pada port SMB/NetBIOS. Pola penyebaran ransomware!"
                return self._format_alert(category, src_ip, dst_port, description, payload_text)

        if dst_port == 3389:
            if len(payload_data) > 0:
                category = "HACKER"
                description = "Upaya pembajakan atau pengintipan layar Windows Remote Desktop."
                return self._format_alert(category, src_ip, dst_port, description, payload_text)

        if dst_port == 5900:
            if len(payload_data) > 0:
                category = "VIRUS"
                description = "Upaya akses ilegal ke VNC Remote Control."
                return self._format_alert(category, src_ip, dst_port, description, payload_text)

        # 4. Port tinggi (>= 49152) dengan payload berbahaya
        if dst_port >= 49152:
            if len(payload_data) > 0 and any(cmd in payload_lower for cmd in self.dangerous_cmds):
                category = "TROJAN"
                description = f"Payload perintah shell berbahaya di Port Tinggi {dst_port}!"
                return self._format_alert(category, src_ip, dst_port, description, payload_text)

        return None

    def _process_udp(self, packet):
        src_ip = packet.src_addr
        dst_port = packet.dst_port
        payload_data = b""
        try:
            if packet.payload:
                payload_data = bytes(packet.payload)
        except AttributeError:
            pass

        if len(payload_data) > 2048:
            return None

        payload_text = payload_data.decode('utf-8', errors='ignore').strip()
        payload_lower = payload_text.lower()

        # Contoh: deteksi DNS tunneling atau payload tidak biasa
        if dst_port == 53 and len(payload_data) > 0 and any(x in payload_lower for x in ["cmd", "exec", "powershell"]):
            category = "TROJAN"
            description = "Kemungkinan DNS tunneling atau eksfiltrasi data."
            return self._format_alert(category, src_ip, dst_port, description, payload_text)

        return None

    def _format_alert(self, category, src_ip, dst_port, description, payload_text=""):
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
