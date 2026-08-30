import pydivert
import threading
from src.honeypot import SBSHoneypot

class InterceptorWorker(threading.Thread):
    def __init__(self):
        super().__init__()
        self.is_running = True
        self._handle = None
        # Filter semua paket TCP dan UDP untuk analisis menyeluruh
        # Honeypot akan memutuskan apakah paket mencurigakan.
        self.filter_rule = "tcp or udp"
        self.honeypot_engine = SBSHoneypot()
        self.log_queue = None

    def emit_log(self, msg):
        if self.log_queue:
            self.log_queue.put(msg)

    def emit_status(self, text, color):
        self.emit_log(f"[STATUS] {text}|{color}")

    def run(self):
        init_msg = self.honeypot_engine.process_system_info("Menginisialisasi Radar Ancaman Siber SBS...")
        self.emit_log(init_msg)

        try:
            self._handle = pydivert.WinDivert(self.filter_rule)
            self._handle.open()

            self.emit_status("RADAR AKTIF", "#00FF00")
            filter_msg = self.honeypot_engine.process_system_info(
                "Radar Jaringan Side-by-Side Siaga. Mode Non-Bloking Aktif (Paket Diteruskan)"
            )
            self.emit_log(filter_msg)

            while self.is_running:
                packet = self._handle.recv()
                if not self.is_running:
                    break

                # Analisis ancaman (tidak memblokir, hanya logging)
                gui_alert = self.honeypot_engine.process_packet(packet)
                if gui_alert:
                    self.emit_log(gui_alert)

                # PENTING: Selalu re-inject paket agar internet tetap jalan
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
