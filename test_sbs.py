import socket
import threading
import time
import random

def start_listener(port):
    """Membuat server lokal sederhana agar koneksi berhasil dan payload terkirim"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', port))
        server.listen(1)
        conn, addr = server.accept()
        data = conn.recv(1024)
        conn.close()
    except Exception:
        pass
    finally:
        server.close()

def test_port(port, payload=None):
    print(f"🔍 Mengirim paket ke Port {port}...")
    listener = threading.Thread(target=start_listener, args=(port,), daemon=True)
    listener.start()
    time.sleep(0.2)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(('127.0.0.1', port))
        if payload:
            s.send(payload.encode())
            print(f"   -> Payload terkirim: {payload}")
        else:
            print(f"   -> Koneksi berhasil dibuat.")
        s.close()
    except Exception as e:
        print(f"   -> Koneksi gagal (tapi paket tetap tertangkap radar): {e}")
    time.sleep(0.5)

def port_scan_test():
    """Simulasi port scanning dengan SYN ke 15 port berbeda"""
    print("\n🚀 Memulai simulasi PORT SCANNING (15 port)...")
    for i in range(15):
        port = random.randint(1000, 9999)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(('127.0.0.1', port))
            s.close()
        except:
            pass
        time.sleep(0.1)

def rdp_brute_force():
    """Simulasi 12 koneksi ke RDP (port 3389) - tanpa payload"""
    print("\n🚀 Memulai simulasi BRUTE-FORCE RDP (12 koneksi)...")
    for i in range(12):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(('127.0.0.1', 3389))
            s.close()
        except:
            pass
        time.sleep(0.1)

print("🚀 Memulai Simulasi Serangan ke SBS...\n")

# 1. Tes RANSOMWARE (Port 445 - SMB) - hanya SYN biasa, seharusnya TIDAK terdeteksi
test_port(445)

# 2. Tes HACKER (Port 3389 - RDP) - hanya SYN, seharusnya TIDAK terdeteksi
test_port(3389)

# 3. Tes TROJAN (Port Tinggi 49152 dengan payload Reverse Shell)
test_port(49152, "powershell -c whoami")

# 4. Tes MALWARE (Port 8080 dengan SQL Injection)
test_port(8080, "name=' OR '1'='1")

# 5. Tes EXPLOIT SMB (Payload dengan null bytes - EternalBlue)
test_port(445, "\x00\x00\x00\x00\x00\x00")

# 6. Tes PORT SCANNING (15 port)
port_scan_test()

# 7. Tes BRUTE-FORCE RDP (12 koneksi)
rdp_brute_force()

print("\n✅ Pengujian selesai! Sekarang cek GUI SBS di Tab 'Live Monitor', 'Tabular Forensic Database', dan 'Forensic & Tracking'.")