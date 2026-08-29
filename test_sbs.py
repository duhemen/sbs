import socket
import threading
import time

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
        # Port < 1024 mungkin butuh admin, tapi honeypot tetap menangkap SYN
        pass
    finally:
        server.close()

def test_port(port, payload=None):
    print(f"🔍 Mengirim paket ke Port {port}...")
    # Mulai listener di thread terpisah
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

print("🚀 Memulai Simulasi Serangan ke SBS...\n")

# 1. Tes RANSOMWARE (Port 445 - SMB)
test_port(445)

# 2. Tes HACKER (Port 3389 - RDP)
test_port(3389)

# 3. Tes TROJAN (Port Tinggi 49152 dengan payload Reverse Shell)
test_port(49152, "powershell -c whoami")

# 4. Tes MALWARE (Port 8080 dengan SQL Injection)
test_port(8080, "name=' OR '1'='1")

print("\n✅ Pengujian selesai! Sekarang cek GUI SBS di Tab 'Live Monitor' dan 'Tabular Forensic Database'.")