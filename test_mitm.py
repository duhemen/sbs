from scapy.all import ARP, Ether, sendp, IP, TCP, UDP, ICMP, send, Raw
import socket
import subprocess
import re
import time

# ==================== MITM TEST ====================
def test_mitm():
    print("\n=== Testing MITM (ARP Spoofing) ===")
    # Dapatkan IP lokal
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()

    # Dapatkan gateway default IPv4
    result = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True)
    gateway = None
    for line in result.stdout.split('\n'):
        if "0.0.0.0" in line and "On-link" not in line:
            parts = line.split()
            if len(parts) >= 4 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[3]):
                gateway = parts[3]
                break
    if not gateway:
        gateway = local_ip.rsplit('.', 1)[0] + ".1"

    fake_mac = "00:11:22:33:44:55"

    # Kirim ARP reply palsu ke IP lokal
    packet1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gateway, pdst=local_ip, hwsrc=fake_mac)
    sendp(packet1, verbose=False)
    print(f"1. ARP Spoofing dikirim: {gateway} -> {local_ip} (MAC {fake_mac})")

    # Kirim ARP reply broadcast
    packet2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gateway, pdst="255.255.255.255", hwsrc=fake_mac)
    sendp(packet2, verbose=False)
    print("2. ARP Spoofing broadcast dikirim.")

# ==================== ICMP FLOOD TEST ====================
def test_icmp_flood():
    print("\n=== Testing ICMP Flood (DoS) ===")
    target_ip = "127.0.0.1"
    count = 60
    print(f"Mengirim {count} paket ICMP echo request ke {target_ip}...")
    packet = IP(dst=target_ip) / ICMP()
    for i in range(count):
        send(packet, verbose=False)
        time.sleep(0.01)

# ==================== ICMP TUNNELING TEST ====================
def test_icmp_tunneling():
    print("\n=== Testing ICMP Tunneling (Eksfiltrasi Data) ===")
    target_ip = "127.0.0.1"
    # Payload berisi kata kunci yang dideteksi honeypot (cmd, powershell, exec)
    payload_data = b"powershell -enc SQBFAFgA"  # contoh encoded command
    packet = IP(dst=target_ip) / ICMP() / Raw(load=payload_data)
    # Kirim 1 paket dengan payload > 100 byte agar terdeteksi
    send(packet, verbose=False)
    print("ICMP tunneling packet dengan payload >100 byte dikirim.")

# ==================== UDP FLOOD TEST ====================
def test_udp_flood():
    print("\n=== Testing UDP Flood (DoS) ===")
    target_ip = "127.0.0.1"
    port = 53
    count = 60
    print(f"Mengirim {count} paket UDP ke {target_ip}:{port}...")
    payload = b"X" * 100
    packet = IP(dst=target_ip) / UDP(dport=port) / payload
    for i in range(count):
        send(packet, verbose=False)
        time.sleep(0.01)

# ==================== C2 TEST (single connection) ====================
def test_c2():
    print("\n=== Testing C2 Detection (Koneksi Tunggal) ===")
    c2_ip = "45.155.205.233"
    print(f"Mengirim SYN ke C2 server {c2_ip}...")
    packet = IP(dst=c2_ip) / TCP(dport=443, flags='S')
    send(packet, verbose=False)
    print("SYN dikirim.")

# ==================== C2 BEACONING TEST ====================
def test_c2_beaconing():
    print("\n=== Testing C2 Beaconing (Komunikasi Periodik) ===")
    c2_ip = "45.155.205.233"
    print(f"Mengirim 3 SYN ke {c2_ip} dalam 60 detik...")
    for i in range(3):
        packet = IP(dst=c2_ip) / TCP(dport=443, flags='S')
        send(packet, verbose=False)
        time.sleep(1)
    print("3 SYN dikirim (harus terdeteksi sebagai beaconing).")

# ==================== SQL INJECTION ON NON-WEB PORT TEST ====================
def test_sql_injection_port():
    print("\n=== Testing SQL Injection pada Port Database (3306) ===")
    target_ip = "127.0.0.1"
    port = 3306  # MySQL
    payload = "union select 1,2,3"
    print(f"Mengirim payload SQL ke {target_ip}:{port}...")
    packet = IP(dst=target_ip) / TCP(dport=port, flags='PA') / Raw(load=payload)
    send(packet, verbose=False)
    print("Payload SQL dikirim.")

# ==================== SSL STRIPPING TEST ====================
def test_ssl_stripping():
    print("\n=== Testing SSL Stripping ===")
    # Kirim SYN ke port 443 dulu
    packet_https = IP(dst="127.0.0.1") / TCP(dport=443, flags='S')
    send(packet_https, verbose=False)
    time.sleep(1)
    # Kirim SYN ke port 80 (HTTP) setelahnya
    packet_http = IP(dst="127.0.0.1") / TCP(dport=80, flags='S')
    send(packet_http, verbose=False)
    print("SYN ke 443 lalu 80 dikirim (harus dalam 10 detik).")

# ==================== MAIN ====================
if __name__ == "__main__":
    print("=== SBS Advanced Features Testing ===")
    test_mitm()
    test_icmp_flood()
    test_icmp_tunneling()
    test_udp_flood()
    test_c2()
    test_c2_beaconing()
    test_sql_injection_port()
    test_ssl_stripping()
    print("\nSelesai. Cek SBS untuk deteksi.")