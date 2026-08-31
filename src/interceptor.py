import pydivert
import threading
from src.honeypot import SBSHoneypot

class InterceptorWorker(threading.Thread):
    def __init__(self):
        super().__init__()
        self.is_running = True
        self._handle = None
        self.filter_candidates = [
            "arp or ip or icmp",
            "ip or arp or icmp",
            "ip",
        ]
        self.honeypot_engine = SBSHoneypot()
        self.log_queue = None
        self.arp_enabled = False

    def emit_log(self, msg):
        if self.log_queue:
            self.log_queue.put(msg)

    def emit_status(self, text, color):
        self.emit_log(f"[STATUS] {text}|{color}")

    def open_handle(self):
        for filt in self.filter_candidates:
            try:
                handle = pydivert.WinDivert(filt)
                handle.open()
                if "arp" in filt:
                    self.arp_enabled = True
                return handle, filt
            except Exception:
                continue
        raise Exception("Tidak ada filter WinDivert yang valid.")

    def arp_sniff_worker(self):
        try:
            from scapy.all import sniff
            self.emit_log("[INFO] Scapy ARP sniffing dimulai...")
            def handle_packet(packet):
                if not self.is_running:
                    return
                if packet.haslayer('ARP'):
                    # Hanya log jika ada perubahan MAC (untuk hindari spam)
                    alert = self.honeypot_engine.process_arp_scapy(packet)
                    if alert:
                        self.emit_log(alert)
            sniff(filter="arp", prn=handle_packet, store=False, stop_filter=lambda p: not self.is_running)
        except Exception as e:
            self.emit_log(f"[INFO] Scapy ARP sniffing gagal: {e}")

    def run(self):
        init_msg = self.honeypot_engine.process_system_info("Menginisialisasi Radar Ancaman Siber SBS...")
        self.emit_log(init_msg)

        try:
            self._handle, used_filter = self.open_handle()
            self.emit_status("RADAR AKTIF", "#00FF00")
            if self.arp_enabled:
                filter_msg = self.honeypot_engine.process_system_info(
                    f"Radar aktif dengan filter '{used_filter}' (deteksi ARP/MITM via WinDivert)."
                )
            else:
                filter_msg = self.honeypot_engine.process_system_info(
                    f"Radar aktif dengan filter '{used_filter}'. Deteksi ARP/MITM menggunakan Scapy."
                )
            self.emit_log(filter_msg)

            # Mulai thread sniffing ARP dengan Scapy
            arp_thread = threading.Thread(target=self.arp_sniff_worker, daemon=True)
            arp_thread.start()

            while self.is_running:
                packet = self._handle.recv()
                if not self.is_running:
                    break
                gui_alert = self.honeypot_engine.process_packet(packet)
                if gui_alert:
                    self.emit_log(gui_alert)
                try:
                    self._handle.send(packet)
                except Exception:
                    pass

        except Exception as e:
            if self.is_running:
                err_msg = self.honeypot_engine.process_system_info(f"Terjadi kesalahan sistem: {e}")
                self.emit_log(f"❌ {err_msg}")
                self.emit_status("ERROR SISTEM", "#EF4444")
        finally:
            self.cleanup()

    def cleanup(self):
        if self._handle:
            try:
                self._handle.close()
            except Exception:
                pass
            self._handle = None

    def stop(self):
        self.is_running = False
        if self._handle:
            try:
                self._handle.close()
            except Exception:
                pass
            self._handle = None
        stop_msg = self.honeypot_engine.process_system_info("Menonaktifkan radar ancaman...")
        self.emit_log(stop_msg)
