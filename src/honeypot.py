# src/honeypot.py
import time
import collections
from src.logger import SBSLogger

class SBSHoneypot:
    def __init__(self):
        self.logger = SBSLogger()
        self.safe_ports = {80, 443, 53, 123}

        # Stateful tracking
        self.syn_count = collections.defaultdict(lambda: {"count": 0, "time": time.time(), "ports": set()})
        self.rdp_attempts = collections.defaultdict(lambda: {"count": 0, "time": time.time()})
        self.ssh_attempts = collections.defaultdict(lambda: {"count": 0, "time": time.time()})
        self.icmp_count = collections.defaultdict(lambda: {"count": 0, "time": time.time(), "last_detect": 0})
        self.udp_count = collections.defaultdict(lambda: {"count": 0, "time": time.time(), "ports": set(), "last_detect": 0})
        self.arp_table = {}  # {ip: mac_address}
        self.ssl_strip_tracker = collections.defaultdict(lambda: {"last_https": 0, "last_detect": 0})
        self.c2_cooldown = collections.defaultdict(lambda: time.time() - 60)
        self.beacon_tracker = collections.defaultdict(list)

        # Signature exploit
        self.exploit_patterns = [
            b"\x00\x00\x00\x00",  # EternalBlue
            b"GIF89a",
            b"<?php",
            b"cmd.exe",
            b"/bin/sh",
            b"powershell -enc",
            b"Metasploit",
        ]

        # Daftar IP jahat (C2)
        self.malicious_ips = {
            "45.155.205.233": "C2 Server",
            "185.220.101.34": "C2 Server",
            "103.75.190.11": "C2 Server",
            "185.220.101.35": "C2 Server",
        }

    # ========== ARP (dari WinDivert) ==========
    def process_arp(self, packet):
        try:
            src_ip = packet.arp.src_ip
            src_mac = packet.arp.src_mac
            opcode = packet.arp.opcode  # 1=Request, 2=Reply
            if opcode != 2:
                return None

            if src_ip in self.arp_table:
                if self.arp_table[src_ip] != src_mac:
                    category = "MITM"
                    description = f"ARP Spoofing terdeteksi! IP {src_ip} mengklaim MAC berubah dari {self.arp_table[src_ip]} ke {src_mac}."
                    self.arp_table[src_ip] = src_mac
                    return self._format_alert(category, src_ip, None, 0, description, "")
            else:
                self.arp_table[src_ip] = src_mac
        except Exception:
            pass
        return None

    # ========== ARP (dari Scapy) ==========
    def process_arp_scapy(self, packet):
        try:
            from scapy.all import ARP
            if packet.haslayer(ARP):
                arp = packet[ARP]
                src_ip = arp.psrc
                src_mac = arp.hwsrc
                if arp.op == 2:  # ARP Reply
                    if src_ip in self.arp_table:
                        if self.arp_table[src_ip] != src_mac:
                            category = "MITM"
                            description = f"ARP Spoofing terdeteksi! IP {src_ip} mengklaim MAC berubah dari {self.arp_table[src_ip]} ke {src_mac}."
                            self.arp_table[src_ip] = src_mac
                            return self._format_alert(category, src_ip, None, 0, description, "")
                    else:
                        self.arp_table[src_ip] = src_mac
        except Exception:
            pass
        return None

    # ========== ICMP ==========
    def process_icmp(self, packet):
        src_ip = packet.src_addr
        current_time = time.time()
        record = self.icmp_count[src_ip]

        # ICMP Tunneling
        payload = getattr(packet, 'payload', b"") or b""
        if len(payload) > 100 and any(b in payload for b in [b'cmd', b'powershell', b'exec']):
            category = "TROJAN"
            description = f"ICMP Tunneling / eksfiltrasi data terdeteksi dari {src_ip}! Payload: {payload[:30]}"
            return self._format_alert(category, src_ip, None, 0, description, "")

        # ICMP Flood
        if current_time - record["time"] > 5:
            record["count"] = 0
            record["time"] = current_time
        record["count"] += 1
        if record["count"] >= 50 and (current_time - record["last_detect"] > 10):
            category = "DoS"
            description = f"ICMP Flood terdeteksi! {record['count']} paket dari {src_ip} dalam 5 detik."
            record["count"] = 0
            record["last_detect"] = current_time
            return self._format_alert(category, src_ip, None, 0, description, "")
        return None

    # ========== TCP ==========
    def process_tcp(self, packet):
        src_ip = packet.src_addr
        dst_ip = packet.dst_addr
        dst_port = packet.dst_port
        tcp_header = packet.tcp
        syn = tcp_header.syn
        ack = tcp_header.ack
        payload_data = getattr(packet, 'payload', b"") or b""
        payload_text = payload_data.decode('utf-8', errors='ignore').strip()
        payload_lower = payload_text.lower()

        # Deteksi C2 (dst_ip jahat)
        if dst_ip in self.malicious_ips:
            now = time.time()
            beacon_records = self.beacon_tracker[src_ip]
            beacon_records = [t for t in beacon_records if now - t < 60]
            beacon_records.append(now)
            self.beacon_tracker[src_ip] = beacon_records
            if len(beacon_records) >= 3:
                category = "C2"
                description = f"C2 Beaconing terdeteksi! IP {src_ip} berkomunikasi ke {dst_ip} ({self.malicious_ips[dst_ip]}) {len(beacon_records)} kali dalam 60 detik."
                self.beacon_tracker[src_ip] = []
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)
            if now - self.c2_cooldown[dst_ip] > 30:
                category = "C2"
                description = f"Koneksi ke C2 Server terdeteksi! IP {dst_ip} dikenal sebagai {self.malicious_ips[dst_ip]}."
                self.c2_cooldown[dst_ip] = now
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)

        # Deteksi C2 (src_ip jahat)
        if src_ip in self.malicious_ips:
            now = time.time()
            if now - self.c2_cooldown[src_ip] > 30:
                category = "C2"
                description = f"Koneksi dari C2 Server terdeteksi! IP {src_ip} dikenal sebagai {self.malicious_ips[src_ip]}."
                self.c2_cooldown[src_ip] = now
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)

        # Deteksi SSL Stripping
        if dst_port == 443 and syn and not ack:
            self.ssl_strip_tracker[src_ip]["last_https"] = time.time()
        if dst_port == 80 and syn and not ack:
            ssl_record = self.ssl_strip_tracker[src_ip]
            now = time.time()
            if now - ssl_record["last_https"] < 10 and now - ssl_record["last_detect"] > 30:
                category = "SUSPICIOUS"
                description = "Potensi SSL Stripping: koneksi HTTP setelah HTTPS dari IP yang sama."
                ssl_record["last_detect"] = now
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)

        # SQL Injection pada port database
        if dst_port in {3306, 5432, 27017} and payload_data:
            if any(x in payload_lower for x in ["union select", "or 1=1", "<script>", "drop table", "select * from"]):
                category = "MALWARE"
                description = f"Percobaan SQL Injection pada port database {dst_port}!"
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)

        # Port Scan
        if syn and not ack:
            current_time = time.time()
            record = self.syn_count[src_ip]
            if current_time - record["time"] > 10:
                record["count"] = 0
                record["ports"] = set()
                record["time"] = current_time
            record["count"] += 1
            record["ports"].add(dst_port)
            if len(record["ports"]) >= 10 and (current_time - record["time"] <= 5):
                category = "HACKER"
                description = f"Port Scanning agresif! Menyerang {len(record['ports'])} port berbeda (contoh: {dst_port})."
                record["count"] = 0
                record["ports"] = set()
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, "")
            if dst_port in {445, 139}:
                return None

        # Exploit SMB
        if dst_port in {135, 137, 139, 445}:
            if any(sig in payload_data for sig in self.exploit_patterns):
                category = "RANSOMWARE"
                description = f"Eksploitasi SMB! Payload mengandung signature {payload_data[:20]}..."
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)
            if len(payload_data) > 100:
                category = "RANSOMWARE"
                description = "Aktivitas SMB mencurigakan dengan payload besar (potensi exploit)."
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)

        # Brute-force RDP & SSH
        if dst_port == 3389:
            now = time.time()
            if now - self.rdp_attempts[src_ip]["time"] > 30:
                self.rdp_attempts[src_ip]["count"] = 0
                self.rdp_attempts[src_ip]["time"] = now
            self.rdp_attempts[src_ip]["count"] += 1
            if len(payload_data) > 200:
                category = "HACKER"
                description = "Potensi serangan RDP (BlueKeep) atau pembajakan sesi."
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)
            if self.rdp_attempts[src_ip]["count"] >= 10:
                category = "HACKER"
                description = "Percobaan Brute-Force RDP terdeteksi!"
                self.rdp_attempts[src_ip]["count"] = 0
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)

        if dst_port == 22:
            now = time.time()
            if now - self.ssh_attempts[src_ip]["time"] > 30:
                self.ssh_attempts[src_ip]["count"] = 0
                self.ssh_attempts[src_ip]["time"] = now
            self.ssh_attempts[src_ip]["count"] += 1
            if self.ssh_attempts[src_ip]["count"] >= 10:
                category = "HACKER"
                description = "Percobaan Brute-Force SSH terdeteksi!"
                self.ssh_attempts[src_ip]["count"] = 0
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, "")

        # Web Shell / SQL Injection (Port Web)
        if dst_port in {80, 8080, 8443}:
            if b"<?php" in payload_data or b"GIF89a" in payload_data or b"cmd.exe" in payload_data:
                category = "MALWARE"
                description = "Potensi Web Shell atau injeksi PHP berbahaya!"
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)
            if "union select" in payload_lower or "<script>" in payload_lower:
                category = "MALWARE"
                description = "Percobaan SQL Injection / XSS pada Web Server."
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)

        # Port Tinggi dengan Payload Jahat
        if dst_port >= 49152:
            if any(cmd in payload_lower for cmd in ["powershell", "cmd.exe", "bash -c", "nc -e"]):
                category = "TROJAN"
                description = f"Reverse Shell / Payload berbahaya di port tinggi {dst_port}!"
                return self._format_alert(category, src_ip, dst_ip, dst_port, description, payload_text)

        return None

    # ========== UDP ==========
    def process_udp(self, packet):
        src_ip = packet.src_addr
        dst_ip = packet.dst_addr
        dst_port = packet.dst_port
        payload_data = getattr(packet, 'payload', b"") or b""
        payload_lower = payload_data.decode('utf-8', errors='ignore').lower()

        # UDP Flood
        current_time = time.time()
        record = self.udp_count[src_ip]
        if current_time - record["time"] > 5:
            record["count"] = 0
            record["time"] = current_time
            record["ports"] = set()
        record["count"] += 1
        record["ports"].add(dst_port)
        if record["count"] >= 50 and len(record["ports"]) <= 3 and (current_time - record["last_detect"] > 10):
            category = "DoS"
            description = f"UDP Flood terdeteksi! {record['count']} paket ke port {dst_port} dari {src_ip} dalam 5 detik."
            record["count"] = 0
            record["ports"] = set()
            record["last_detect"] = current_time
            return self._format_alert(category, src_ip, dst_ip, dst_port, description, "")

        # DNS Tunneling
        if dst_port == 53 and len(payload_data) > 100 and any(x in payload_lower for x in ["cmd", "powershell", "exec"]):
            category = "TROJAN"
            description = "Kemungkinan DNS Tunneling / Eksfiltrasi Data!"
            return self._format_alert(category, src_ip, dst_ip, dst_port, description, "")

        # SNMP
        if dst_port == 161 and len(payload_data) > 50:
            category = "SUSPICIOUS"
            description = "Potensi eksploitasi SNMP (protocol manajemen jaringan)."
            return self._format_alert(category, src_ip, dst_ip, dst_port, description, "")

        return None

    # ========== Main Processing ==========
    def process_packet(self, packet):
        """Main entry untuk setiap paket dari WinDivert"""
        if getattr(packet, 'arp', None):
            return self.process_arp(packet)
        elif getattr(packet, 'tcp', None):
            return self.process_tcp(packet)
        elif getattr(packet, 'udp', None):
            return self.process_udp(packet)
        elif getattr(packet, 'icmp', None):
            return self.process_icmp(packet)
        return None

    def _format_alert(self, category, src_ip, dst_ip, dst_port, description, payload_text=""):
        if dst_ip:
            attack_detail = f"[{category}] Dari IP: {src_ip} ke {dst_ip} mengetuk Port: {dst_port} -> Analisis: {description}"
        else:
            attack_detail = f"[{category}] Dari IP: {src_ip} mengetuk Port: {dst_port} -> Analisis: {description}"
        if payload_text:
            attack_detail += f" | Payload: {payload_text[:150]}"

        gui_log_msg = self.logger.format_alert(attack_detail)
        self.logger.write_to_file(category, f"IP: {src_ip} -> {dst_ip} | Port: {dst_port} | Payload: {payload_text[:200]}")
        return gui_log_msg

    def process_system_info(self, info_message):
        gui_log_msg = self.logger.format_info(info_message)
        self.logger.write_to_file("INFO", info_message)
        return gui_log_msg
