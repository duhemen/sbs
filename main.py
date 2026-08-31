import os
import datetime
import time
import tkinter as tk
from tkinter import ttk
import queue
import threading
import subprocess
import socket
import urllib.request
import webbrowser
import json
import ipaddress
import re
import csv

from tkinter import filedialog
from src.database import SBSDatabase
from src.interceptor import InterceptorWorker


class SBSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SBS (Side-by-Side) - Enterprise Intrusion Detection System")
        self.root.geometry("1100x700")

        self.stats = {
            "HACKER": 0,
            "RANSOMWARE": 0,
            "VIRUS": 0,
            "SUSPICIOUS": 0,
            "MALWARE": 0,
            "TROJAN": 0,
            "MITM": 0,
            "DoS": 0,
            "C2": 0
        }

        self.worker_thread = None
        self.log_queue = queue.Queue()
        self.selected_ip = None
        self.blocked_ips = {}
        self.db = SBSDatabase()
        self._last_refresh_time = 0

        self.init_ui()
        self.poll_log_queue()

    def init_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background='#0B0F19', foreground='#E2E8F0')
        style.configure('TNotebook', background='#0B0F19', borderwidth=0)
        style.configure('TNotebook.Tab', background='#1E293B', foreground='#94A3B8', padding=[15, 5])
        style.map('TNotebook.Tab', background=[('selected', '#0F172A')], foreground=[('selected', '#38BDF8')])
        style.configure('Treeview', background='#020617', foreground='#E2E8F0', fieldbackground='#020617')
        style.configure('Treeview.Heading', background='#1E293B', foreground='#38BDF8', font=('Arial', 10, 'bold'))

        # HEADER STATUS
        self.status_frame = tk.Frame(self.root, bg='#0F172A', bd=1, relief='solid', highlightbackground='#1E293B')
        self.status_frame.pack(fill='x', padx=10, pady=5)
        self.status_label = tk.Label(self.status_frame, text="STATUS RADAR: NONAKTIF", fg='#EF4444', bg='#0F172A', font=('Arial', 12, 'bold'))
        self.status_label.pack(side='left', padx=10, pady=5)

        # BUTTON PANEL BAWAH
        self.btn_frame = tk.Frame(self.root, bg='#0B0F19')
        self.btn_frame.pack(side='bottom', fill='x', padx=10, pady=10)
        self.btn_start = tk.Button(self.btn_frame, text="AKTIFKAN DEEP RADAR HONEYPOT", bg='#0284C7', fg='white',
                                   font=('Arial', 10, 'bold'), relief='flat', padx=20, pady=8, command=self.start_honeypot)
        self.btn_start.pack(side='left', fill='x', expand=True, padx=5)
        self.btn_stop = tk.Button(self.btn_frame, text="NONAKTIFKAN RADAR", bg='#DC2626', fg='white',
                                  font=('Arial', 10, 'bold'), relief='flat', padx=20, pady=8, state='disabled',
                                  command=self.stop_honeypot)
        self.btn_stop.pack(side='right', fill='x', expand=True, padx=5)

        # TABS
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)

        # TAB 1: Live Monitor
        self.tab1 = tk.Frame(self.notebook, bg='#0F172A')
        self.notebook.add(self.tab1, text=" 🖥️ Live Monitor & Analytics ")
        tk.Label(self.tab1, text="Live Traffic Logs:", bg='#0F172A', fg='#38BDF8',
                 font=('Arial', 10, 'bold')).pack(anchor='w', padx=10, pady=5)
        self.log_monitor = tk.Text(self.tab1, bg='#020617', fg='#38BDF8', insertbackground='white',
                                   font=('Consolas', 10), relief='solid', bd=1)
        self.log_monitor.pack(fill='both', expand=True, padx=10, pady=2)
        tk.Label(self.tab1, text="Intelligence Analytics Engine (What-If / Then-What):",
                 bg='#0F172A', fg='#10B981', font=('Arial', 10, 'bold')).pack(anchor='w', padx=10, pady=5)
        self.analytics_monitor = tk.Text(self.tab1, bg='#090D16', fg='#10B981', height=4,
                                         font=('Consolas', 10), relief='solid', bd=1)
        self.analytics_monitor.insert('1.0', "[INTELLIGENCE] Sistem siaga. Menunggu aktivitas jaringan...")
        self.analytics_monitor.config(state='disabled')
        self.analytics_monitor.pack(fill='x', padx=10, pady=5)

        # TAB 2: Graphical Dashboard
        self.tab2 = tk.Frame(self.notebook, bg='#0F172A')
        self.notebook.add(self.tab2, text=" 📊 Graphical Dashboard ")
        tk.Label(self.tab2, text="Visualisasi Kuantitas Frekuensi Ancaman Siber",
                 bg='#0F172A', fg='#38BDF8', font=('Arial', 11, 'bold')).pack(pady=10)
        self.canvas = tk.Canvas(self.tab2, bg='#020617', highlightthickness=1,
                                highlightbackground='#1E293B')
        self.canvas.pack(fill='both', expand=True, padx=20, pady=10)
        self.canvas.bind("<Configure>", lambda e: self.update_charts())

        # TAB 3: Tabular Forensic Database
        self.tab3 = tk.Frame(self.notebook, bg='#0F172A')
        self.notebook.add(self.tab3, text=" 📋 Tabular Forensic Database ")

        self.log_table = ttk.Treeview(self.tab3, columns=("Waktu", "IP", "Port", "Kategori", "Rekomendasi"),
                                      show='headings', height=8)
        self.log_table.heading("Waktu", text="Waktu Kejadian")
        self.log_table.heading("IP", text="IP Penyerang")
        self.log_table.heading("Port", text="Port Target")
        self.log_table.heading("Kategori", text="Klasifikasi Kategori")
        self.log_table.heading("Rekomendasi", text="Rekomendasi Tindakan (Then-What)")
        self.log_table.column("Waktu", width=140)
        self.log_table.column("IP", width=120)
        self.log_table.column("Port", width=80)
        self.log_table.column("Kategori", width=180)
        self.log_table.column("Rekomendasi", width=250)
        self.log_table.pack(fill='both', expand=True, padx=10, pady=5)
        self.log_table.bind("<<TreeviewSelect>>", self.on_table_select)

        self.action_panel = tk.Frame(self.tab3, bg='#0B0F19')
        self.action_panel.pack(fill='x', padx=10, pady=5)
        tk.Label(self.action_panel, text="⚡ ACTION CENTER:", bg='#0B0F19', fg='#38BDF8',
                 font=('Arial', 10, 'bold')).pack(side='left', padx=5)

        self.btn_isolate = tk.Button(self.action_panel, text="🔒 ISOLATE", bg='#DC2626', fg='white',
                                     font=('Arial', 9, 'bold'), relief='flat', padx=10, state='disabled',
                                     command=self.action_isolate)
        self.btn_isolate.pack(side='left', padx=5)
        self.btn_release = tk.Button(self.action_panel, text="🔓 RELEASE", bg='#F59E0B', fg='white',
                                     font=('Arial', 9, 'bold'), relief='flat', padx=10, state='disabled',
                                     command=self.action_release)
        self.btn_release.pack(side='left', padx=5)
        self.btn_check = tk.Button(self.action_panel, text="🔍 CHECK", bg='#0284C7', fg='white',
                                   font=('Arial', 9, 'bold'), relief='flat', padx=10, state='disabled',
                                   command=self.action_check)
        self.btn_check.pack(side='left', padx=5)
        self.btn_block = tk.Button(self.action_panel, text="🚫 BLOCK", bg='#EF4444', fg='white',
                                   font=('Arial', 9, 'bold'), relief='flat', padx=10, state='disabled',
                                   command=self.action_block)
        self.btn_block.pack(side='left', padx=5)
        self.btn_unblock = tk.Button(self.action_panel, text="✅ UNBLOCK", bg='#10B981', fg='white',
                                     font=('Arial', 9, 'bold'), relief='flat', padx=10, state='disabled',
                                     command=self.action_unblock)
        self.btn_unblock.pack(side='left', padx=5)

        tk.Label(self.tab3, text="📌 Daftar Isolasi / Blokir Aktif:", bg='#0F172A', fg='#F59E0B',
                 font=('Arial', 10, 'bold')).pack(anchor='w', padx=10, pady=5)
        self.block_table = ttk.Treeview(self.tab3, columns=("IP", "Tipe", "Waktu", "Rule"),
                                        show='headings', height=5)
        self.block_table.heading("IP", text="IP Address")
        self.block_table.heading("Tipe", text="Tipe (Isolate/Block)")
        self.block_table.heading("Waktu", text="Waktu Aksi")
        self.block_table.heading("Rule", text="Rule Name")
        self.block_table.column("IP", width=150)
        self.block_table.column("Tipe", width=100)
        self.block_table.column("Waktu", width=150)
        self.block_table.column("Rule", width=250)
        self.block_table.pack(fill='x', padx=10, pady=5)

        # TAB 4: Forensic & Tracking
        self.tab4 = tk.Frame(self.notebook, bg='#0F172A')
        self.notebook.add(self.tab4, text=" 🔍 Forensic & Tracking ")

        map_frame = tk.Frame(self.tab4, bg='#0B0F19', bd=1, relief='solid')
        map_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        tk.Label(map_frame, text="🗺️ Mapping Hasil Deteksi (Geo-Location IP)",
                 bg='#0B0F19', fg='#38BDF8', font=('Arial', 10, 'bold')).pack(pady=5)

        self.map_canvas = tk.Canvas(map_frame, bg='#020617', highlightthickness=0)
        self.map_canvas.pack(fill='both', expand=True, padx=5, pady=5)
        self.map_canvas.bind("<Configure>", lambda e: self.draw_map())

        right_frame = tk.Frame(self.tab4, bg='#0B0F19')
        right_frame.pack(side='right', fill='both', expand=True, padx=5, pady=5)

        db_label = tk.Label(right_frame, text="📁 Database Hasil Deteksi",
                            bg='#0B0F19', fg='#10B981', font=('Arial', 10, 'bold'))
        db_label.pack(anchor='w', padx=5, pady=2)

        self.forensic_table = ttk.Treeview(right_frame,
                                           columns=("Waktu", "IP", "Port", "Kategori", "Negara", "Kota"),
                                           show='headings', height=8)
        self.forensic_table.heading("Waktu", text="Waktu")
        self.forensic_table.heading("IP", text="IP Penyerang")
        self.forensic_table.heading("Port", text="Port")
        self.forensic_table.heading("Kategori", text="Kategori")
        self.forensic_table.heading("Negara", text="Negara")
        self.forensic_table.heading("Kota", text="Kota")
        self.forensic_table.column("Waktu", width=130)
        self.forensic_table.column("IP", width=110)
        self.forensic_table.column("Port", width=60)
        self.forensic_table.column("Kategori", width=120)
        self.forensic_table.column("Negara", width=100)
        self.forensic_table.column("Kota", width=120)
        self.forensic_table.pack(fill='both', expand=True, padx=5, pady=5)
        self.forensic_table.bind("<<TreeviewSelect>>", self.on_forensic_table_select)

        trace_label = tk.Label(right_frame, text="🕵️ Tracing / Riwayat Aktivitas IP",
                               bg='#0B0F19', fg='#F59E0B', font=('Arial', 10, 'bold'))
        trace_label.pack(anchor='w', padx=5, pady=(10, 2))

        self.trace_table = ttk.Treeview(right_frame,
                                        columns=("Waktu", "Port", "Kategori", "Aktivitas"),
                                        show='headings', height=8)
        self.trace_table.heading("Waktu", text="Waktu")
        self.trace_table.heading("Port", text="Port")
        self.trace_table.heading("Kategori", text="Kategori")
        self.trace_table.heading("Aktivitas", text="Aktivitas")
        self.trace_table.column("Waktu", width=130)
        self.trace_table.column("Port", width=60)
        self.trace_table.column("Kategori", width=120)
        self.trace_table.column("Aktivitas", width=250)
        self.trace_table.pack(fill='both', expand=True, padx=5, pady=5)

        rt_label = tk.Label(right_frame, text="⚡ Pemantauan Realtime",
                            bg='#0B0F19', fg='#EF4444', font=('Arial', 10, 'bold'))
        rt_label.pack(anchor='w', padx=5, pady=(10, 2))

        self.realtime_log = tk.Text(right_frame, bg='#020617', fg='#94A3B8', height=8,
                                    font=('Consolas', 9), relief='solid', bd=1)
        self.realtime_log.pack(fill='both', expand=True, padx=5, pady=5)

        btn_frame4 = tk.Frame(self.tab4, bg='#0B0F19')
        btn_frame4.pack(side='bottom', fill='x', padx=5, pady=5)

        btn_refresh = tk.Button(btn_frame4, text="🔄 Refresh Database", bg='#0284C7', fg='white',
                                font=('Arial', 9, 'bold'), command=self.refresh_forensic_tab)
        btn_refresh.pack(side='left', fill='x', expand=True, padx=5)

        btn_map = tk.Button(btn_frame4, text="🗺️ Buka Peta Interaktif (Folium)", bg='#10B981', fg='white',
                            font=('Arial', 9, 'bold'), command=self.open_interactive_map)
        btn_map.pack(side='left', fill='x', expand=True, padx=5)

        btn_export = tk.Button(btn_frame4, text="📤 Export JSON/CSV", bg='#F59E0B', fg='white',
                               font=('Arial', 9, 'bold'), command=self.export_database)
        btn_export.pack(side='left', fill='x', expand=True, padx=5)

        btn_import = tk.Button(btn_frame4, text="📥 Import JSON", bg='#A855F7', fg='white',
                               font=('Arial', 9, 'bold'), command=self.import_database)
        btn_import.pack(side='left', fill='x', expand=True, padx=5)

    # ===== Method Utilitas =====
    def _is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _run_command(self, cmd_args):
        try:
            result = subprocess.run(cmd_args, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
            return output.strip() if output else "OK"
        except Exception as e:
            return f"ERROR: {str(e)}"

    # ===== Action methods =====
    def action_check(self):
        if not self.selected_ip:
            return
        ip = self.selected_ip
        self.analytics_monitor.config(state='normal')
        self.analytics_monitor.delete('1.0', 'end')
        self.analytics_monitor.insert('1.0', f"⏳ [CHECK] Menganalisis IP {ip}...")
        self.analytics_monitor.config(state='disabled')

        def worker():
            is_local = ip.startswith("127.") or ip == "localhost" or ip.startswith("192.168.") or ip.startswith("10.")
            result = f"🔍 [CHECK RESULT] IP: {ip}\n"
            if is_local:
                result += "   ⚠️ IP ini adalah IP Lokal (Localhost/Internal).\n"
                result += "   Database eksternal tidak memiliki data untuk IP lokal.\n"
            else:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    result += f"   Hostname: {hostname}\n"
                except:
                    result += "   Hostname: Tidak ditemukan\n"

                info = {}
                try:
                    url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as"
                    req = urllib.request.Request(url, headers={'User-Agent': 'SBS'})
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        data = json.loads(resp.read().decode())
                    if data['status'] == 'success':
                        info = data
                except Exception as e:
                    info['error'] = str(e)

                if info and 'status' in info and info['status'] == 'success':
                    if 'country' in info:
                        result += f"   Lokasi: {info['city']}, {info['regionName']}, {info['country']}\n"
                    if 'isp' in info:
                        result += f"   ISP: {info['isp']}\n"
                    if 'org' in info:
                        result += f"   Organisasi: {info['org']}\n"
                    if 'as' in info:
                        result += f"   ASN: {info['as']}\n"
                else:
                    result += "   Info publik tidak tersedia.\n"

            result += "\n🌐 Membuka AbuseIPDB di browser...\n"
            webbrowser.open(f"https://www.abuseipdb.com/check/{ip}")
            self.root.after(0, self._update_analytics, result)
            self.root.after(0, self._log_action, f"[CHECK] Selesai untuk IP {ip}")

        threading.Thread(target=worker, daemon=True).start()

    def action_isolate(self):
        ip = self.selected_ip
        if not ip or not self._is_valid_ip(ip):
            self._update_analytics("❌ IP tidak valid.")
            return
        rule_name = f"SBS_ISOLATE_{ip}"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}",
               "dir=in", "action=block", f"remoteip={ip}"]
        output = self._run_command(cmd)
        if "OK" in output or "Ok." in output:
            self.blocked_ips[ip] = {"type": "isolate", "rule_name": rule_name,
                                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            self.update_block_table()
            self._log_action(f"🔒 [ISOLATE] IP {ip} berhasil diisolasi.")
            self._update_analytics(f"🔒 [ISOLATE] IP {ip} berhasil diisolasi.\n{output}")
            self.on_table_select(None)
        else:
            self._update_analytics(f"❌ [ISOLATE] Gagal: {output}")

    def action_release(self):
        ip = self.selected_ip
        if not ip or not self._is_valid_ip(ip):
            return
        if ip not in self.blocked_ips or self.blocked_ips[ip]["type"] != "isolate":
            self._update_analytics("⚠️ IP ini tidak sedang di-isolate.")
            return
        rule_name = self.blocked_ips[ip]["rule_name"]
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        output = self._run_command(cmd)
        if "OK" in output or "Ok." in output or "No rules match" in output:
            del self.blocked_ips[ip]
            self.update_block_table()
            self._log_action(f"🔓 [RELEASE] IP {ip} dilepas dari isolasi.")
            self._update_analytics(f"🔓 [RELEASE] IP {ip} dilepas.\n{output}")
            self.on_table_select(None)
        else:
            self._update_analytics(f"❌ [RELEASE] Gagal: {output}")

    def action_block(self):
        ip = self.selected_ip
        if not ip or not self._is_valid_ip(ip):
            self._update_analytics("❌ IP tidak valid.")
            return
        rule_name = f"SBS_BLOCK_{ip}"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}",
               "dir=in", "action=block", f"remoteip={ip}"]
        output = self._run_command(cmd)
        if "OK" in output or "Ok." in output:
            self.blocked_ips[ip] = {"type": "block", "rule_name": rule_name,
                                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            self.update_block_table()
            self._log_action(f"🚫 [BLOCK] IP {ip} berhasil diblokir permanen.")
            self._update_analytics(f"🚫 [BLOCK] IP {ip} diblokir.\n{output}")
            self.on_table_select(None)
        else:
            self._update_analytics(f"❌ [BLOCK] Gagal: {output}")

    def action_unblock(self):
        ip = self.selected_ip
        if not ip or not self._is_valid_ip(ip):
            return
        if ip not in self.blocked_ips or self.blocked_ips[ip]["type"] != "block":
            self._update_analytics("⚠️ IP ini tidak sedang diblokir.")
            return
        rule_name = self.blocked_ips[ip]["rule_name"]
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        output = self._run_command(cmd)
        if "OK" in output or "Ok." in output or "No rules match" in output:
            del self.blocked_ips[ip]
            self.update_block_table()
            self._log_action(f"✅ [UNBLOCK] IP {ip} dibuka dari blokir.")
            self._update_analytics(f"✅ [UNBLOCK] IP {ip} di-unblock.\n{output}")
            self.on_table_select(None)
        else:
            self._update_analytics(f"❌ [UNBLOCK] Gagal: {output}")

    def update_block_table(self):
        for item in self.block_table.get_children():
            self.block_table.delete(item)
        for ip, data in self.blocked_ips.items():
            self.block_table.insert("", "end", values=(ip, data["type"], data["time"], data["rule_name"]))

    # ===== UI Update methods =====
    def _update_analytics(self, text):
        self.analytics_monitor.config(state='normal')
        self.analytics_monitor.delete('1.0', 'end')
        self.analytics_monitor.insert('1.0', text)
        self.analytics_monitor.config(state='disabled')

    def _log_action(self, text):
        self.log_monitor.insert('end', f"[ACTION] {text}\n")
        self.log_monitor.see('end')

    def poll_log_queue(self):
        try:
            count = 0
            while count < 10:
                msg = self.log_queue.get_nowait()
                self.append_log(msg)
                if hasattr(self, 'realtime_log'):
                    self.log_to_realtime(msg)
                count += 1
        except queue.Empty:
            pass
        self.root.after(100, self.poll_log_queue)

    def append_log(self, text):
        if text.startswith("[STATUS]"):
            parts = text.split("|", 1)
            if len(parts) == 2:
                status_text = parts[0].replace("[STATUS] ", "").strip()
                color = parts[1].strip()
                self.update_status(status_text, color)
            self.log_monitor.insert('end', text + "\n")
            self.log_monitor.see('end')
            return

        self.log_monitor.insert('end', text + "\n")
        self.log_monitor.see('end')

        if "⚠️ [ALERT]" in text:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                cleaned_text = text.replace("⚠️ [ALERT] ", "")
                cat_part = "SUSPICIOUS"
                for cat in ["RANSOMWARE", "HACKER", "VIRUS", "MALWARE", "TROJAN", "MITM", "DoS", "C2"]:
                    if cat in cleaned_text:
                        cat_part = cat
                        break

                # Ekstraksi src_ip
                ip_match = re.search(r"Dari IP:\s*([\d\.a-fA-F:]+)", cleaned_text)
                if ip_match:
                    src_ip_part = ip_match.group(1)
                else:
                    src_ip_part = "Unknown"

                # Ekstraksi dst_ip (jika ada pola "ke <ip>")
                dst_ip_match = re.search(r"ke\s+([\d\.a-fA-F:]+)", cleaned_text)
                if dst_ip_match:
                    dst_ip_part = dst_ip_match.group(1)
                else:
                    dst_ip_part = None

                # Ekstraksi port (bisa "0" jika tidak ada, atau "ARP" jika MITM)
                port_match = re.search(r"mengetuk Port:\s*(\d+)", cleaned_text)
                if port_match:
                    port_str = port_match.group(1)
                else:
                    port_str = "0"

                # Pisahkan port untuk tampilan vs database
                port_db = int(port_str) if port_str.isdigit() else 0
                port_display = port_str
                if port_db == 0 and "ARP" in cleaned_text.upper():
                    port_display = "ARP"
                    port_db = 0

                # Rekomendasi
                rekomendasi = self.execute_predictive_analytics(cat_part, src_ip_part, port_display)
                self.log_table.insert("", "end", values=(timestamp, src_ip_part, port_display, cat_part, rekomendasi))

                if cat_part not in self.stats:
                    self.stats[cat_part] = 0
                self.stats[cat_part] += 1
                self.save_detection_to_db(timestamp, src_ip_part, dst_ip_part, port_db, cat_part, cleaned_text, rekomendasi)
                self.update_charts()
                self._schedule_refresh()
            except Exception as e:
                self._log_action(f"Error parsing alert: {e}")

    def execute_predictive_analytics(self, category, ip, port):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        if "RANSOMWARE" in category:
            analysis = (f"[{timestamp}] 🧠 [WHAT-IF]: IP {ip} mengeksploitasi Port {port}, virus mengunci dokumen.\n"
                        f"🚨 [THEN-WHAT]: Isolasi jaringan! Matikan SMB (Port 445) dan putus akses IP di router!")
            rekomendasi = "Isolasi jaringan & Matikan SMB!"
        elif "HACKER" in category:
            analysis = (f"[{timestamp}] 🧠 [WHAT-IF]: Ketukan Port {port} dibiarkan, penyerang akan brute-force.\n"
                        f"🔒 [THEN-WHAT]: Ganti kredensial dengan kombinasi kompleks, dan blokir IP tersebut di firewall!")
            rekomendasi = "Ganti kredensial & Blokir IP!"
        elif "MALWARE" in category or "TROJAN" in category:
            analysis = (f"[{timestamp}] 🧠 [WHAT-IF]: Payload dari {ip} mengandung script jahat/malware.\n"
                        f"🛡️ [THEN-WHAT]: Jalankan antivirus, bersihkan file cache, dan update Windows Defender!")
            rekomendasi = "Jalankan antivirus & Hapus file!"
        elif "VIRUS" in category:
            analysis = (f"[{timestamp}] 🧠 [WHAT-IF]: Aktivitas pemindaian virus dari {ip}.\n"
                        f"🛡️ [THEN-WHAT]: Aktifkan Silent Drop untuk membuang paket pencarian secara otomatis!")
            rekomendasi = "Aktifkan Silent Drop!"
        elif "MITM" in category:
            analysis = (f"[{timestamp}] 🧠 [WHAT-IF]: Terjadi ARP Spoofing dari {ip}, lalu lintas dapat disadap.\n"
                        f"🛡️ [THEN-WHAT]: Matikan Wi-Fi, verifikasi MAC gateway, dan gunakan VPN!")
            rekomendasi = "Matikan Wi-Fi & Verifikasi Gateway!"
        elif "DoS" in category:
            analysis = (f"[{timestamp}] 🧠 [WHAT-IF]: Serangan DoS dari {ip} membanjiri jaringan.\n"
                        f"🛡️ [THEN-WHAT]: Blokir IP di firewall dan aktifkan rate limiting!")
            rekomendasi = "Blokir IP & Aktifkan Rate Limiting!"
        elif "C2" in category:
            analysis = (f"[{timestamp}] 🧠 [WHAT-IF]: IP {ip} terhubung ke C2 Server.\n"
                        f"🛡️ [THEN-WHAT]: Putuskan koneksi dan isolasi host tersebut!")
            rekomendasi = "Isolasi Host & Putuskan Koneksi!"
        else:
            analysis = (f"[{timestamp}] 🧠 [WHAT-IF]: Aktivitas pemindaian port acak dari {ip}.\n"
                        f"🛡️ [THEN-WHAT]: Aktifkan Silent Drop untuk membuang paket pencarian secara otomatis!")
            rekomendasi = "Aktifkan Silent Drop!"

        self.analytics_monitor.config(state='normal')
        self.analytics_monitor.delete('1.0', 'end')
        self.analytics_monitor.insert('1.0', analysis)
        self.analytics_monitor.config(state='disabled')
        return rekomendasi

    def update_charts(self):
        self.canvas.delete("all")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 10 or h < 10:
            return

        categories = ["HACKER", "RANSOMWARE", "VIRUS", "MALWARE", "TROJAN", "SUSPICIOUS", "MITM", "DoS", "C2"]
        colors = ["#38BDF8", "#EF4444", "#F59E0B", "#A855F7", "#F97316", "#10B981",
                  "#E11D48", "#DC2626", "#7C3AED"]
        max_val = max(max(self.stats.values()), 1)
        bar_count = len(categories)
        graph_height = h - 80
        bar_width = (w - 100) // bar_count

        for i, cat in enumerate(categories):
            val = self.stats.get(cat, 0)
            bar_h = (val / max_val) * (graph_height - 40)
            x0 = 50 + (i * bar_width) + 20
            y0 = h - 40 - bar_h
            x1 = x0 + bar_width - 40
            y1 = h - 40
            self.canvas.create_rectangle(x0, y0, x1, y1, fill=colors[i], outline="")
            self.canvas.create_text((x0 + x1) // 2, y0 - 15, text=str(val),
                                    fill='white', font=('Arial', 10, 'bold'))
            self.canvas.create_text((x0 + x1) // 2, h - 20, text=cat,
                                    fill='#94A3B8', font=('Arial', 9, 'bold'))

    # ===== Forensic & Tracking methods =====
    def _schedule_refresh(self):
        now = time.time()
        if now - self._last_refresh_time >= 1.0:
            self._last_refresh_time = now
            self.refresh_forensic_tab()

    def refresh_forensic_tab(self):
        """Refresh tabel forensik dan otomatis pilih IP pertama untuk tracing"""
        rows = self.db.get_all_detections()
    
        # Bersihkan tabel forensic
        for item in self.forensic_table.get_children():
            self.forensic_table.delete(item)
    
        # Isi tabel forensic
        for row in rows:
            id_, ts, src_ip, dst_ip, port, cat, payload, rekom, country, city, lat, lon = row
            if dst_ip:
                self.forensic_table.insert("", "end", values=(ts, src_ip, port, cat, country, f"{city} ({dst_ip})"))
            else:
                self.forensic_table.insert("", "end", values=(ts, src_ip, port, cat, country, city))
    
        # Pilih IP pertama jika belum ada IP terpilih
        if not self.selected_ip and rows:
            self.selected_ip = rows[0][2]  # src_ip
        # Selalu update tracing jika ada IP terpilih
        if self.selected_ip:
            self.update_trace_table(self.selected_ip)
    
        # Gambar peta
        self.draw_map()

    def draw_map(self):
        self.map_canvas.delete("all")
        w = self.map_canvas.winfo_width()
        h = self.map_canvas.winfo_height()
        if w < 10 or h < 10:
            return

        self.map_canvas.create_rectangle(0, 0, w, h, fill='#020617', outline='')
        lat_min, lat_max = -60, 85
        lon_min, lon_max = -180, 180

        def project(lat, lon):
            x = (lon - lon_min) / (lon_max - lon_min) * (w - 20) + 10
            y = (lat_max - lat) / (lat_max - lat_min) * (h - 20) + 10
            return x, y

        self.map_canvas.create_line(10, h / 2, w - 10, h / 2, fill='#1E293B', dash=(4, 4))
        self.map_canvas.create_line(w / 2, 10, w / 2, h - 10, fill='#1E293B', dash=(4, 4))

        rows = self.db.get_all_detections()
        for row in rows:
            id_, ts, src_ip, dst_ip, port, cat, payload, rekom, country, city, lat, lon = row
            if lat and lon:
                x, y = project(lat, lon)
                color = "#EF4444"
                self.map_canvas.create_oval(x - 4, y - 4, x + 4, y + 4, fill=color, outline='white')
                self.map_canvas.create_text(x, y - 10, text=src_ip, fill='white', font=('Arial', 7, 'bold'))
            else:
                x, y = w / 2, h / 2
                color = "#38BDF8"
                self.map_canvas.create_oval(x - 4, y - 4, x + 4, y + 4, fill=color, outline='white')
                self.map_canvas.create_text(x, y - 10, text=src_ip, fill='white', font=('Arial', 7, 'bold'))

    def update_trace_table(self, ip):
        """Tampilkan riwayat aktivitas dari IP tertentu"""
        # Bersihkan tabel tracing
        for item in self.trace_table.get_children():
            self.trace_table.delete(item)
    
        try:
            rows = self.db.get_detections_by_ip(ip)
            for row in rows:
                ts, src_ip, dst_ip, dst_port, cat, payload, rekom = row
                # Tampilkan port (jika 0, tampilkan "ARP")
                port_display = dst_port if dst_port else "ARP"
                # Batasi payload agar tidak terlalu panjang
                aktivitas = payload[:50] if payload else "-"
                self.trace_table.insert("", "end", values=(ts, port_display, cat, aktivitas))
        except Exception as e:
            self._log_action(f"Error update_trace_table: {e}")

    def log_to_realtime(self, text):
        self.realtime_log.insert('end', text + "\n")
        self.realtime_log.see('end')

    def save_detection_to_db(self, timestamp, src_ip, dst_ip, dst_port, category, payload, rekomendasi):
        self.db.insert_detection(timestamp, src_ip, dst_ip, dst_port, category, payload, rekomendasi)

        def fetch_geo():
            try:
                import urllib.request
                import json as jsonlib
                url = f"http://ip-api.com/json/{src_ip}?fields=status,country,city,lat,lon"
                req = urllib.request.Request(url, headers={'User-Agent': 'SBS'})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = jsonlib.loads(resp.read().decode())
                if data.get('status') == 'success':
                    self.db.update_geo_info(src_ip, data['country'], data['city'], data['lat'], data['lon'])
                    self.root.after(0, self.refresh_forensic_tab)
            except:
                pass
        threading.Thread(target=fetch_geo, daemon=True).start()

    # ===== Fitur Baru: Peta Interaktif, Export/Import =====
    def open_interactive_map(self):
        try:
            import folium
            rows = self.db.get_all_detections(limit=500)
            m = folium.Map(location=[-6.2088, 106.8456], zoom_start=2)

            # Kumpulkan koordinat unik untuk setiap IP
            ip_coords = {}
            for row in rows:
                id_, ts, src_ip, dst_ip, port, cat, payload, rekom, country, city, lat, lon = row
                if lat and lon:
                    ip_coords[src_ip] = (lat, lon)

            # Warna marker berdasarkan kategori
            cat_colors = {
                "HACKER": "blue",
                "RANSOMWARE": "red",
                "VIRUS": "orange",
                "MALWARE": "purple",
                "TROJAN": "darkred",
                "SUSPICIOUS": "gray",
                "MITM": "pink",
                "DoS": "black",
                "C2": "green"
            }

            # Tambahkan marker
            for row in rows:
                id_, ts, src_ip, dst_ip, port, cat, payload, rekom, country, city, lat, lon = row
                if lat and lon:
                    color = cat_colors.get(cat, "blue")
                    folium.Marker(
                        [lat, lon],
                        popup=f"IP: {src_ip}\nKategori: {cat}\nWaktu: {ts}",
                        icon=folium.Icon(color=color)
                    ).add_to(m)
                    ip_coords[src_ip] = (lat, lon)
                else:
                    ip_coords[src_ip] = (-6.2088, 106.8456)

            # Gambar garis antara src_ip dan dst_ip jika dst_ip punya koordinat
            for row in rows:
                id_, ts, src_ip, dst_ip, port, cat, payload, rekom, country, city, lat, lon = row
                if dst_ip and dst_ip in ip_coords and src_ip in ip_coords:
                    start = ip_coords[src_ip]
                    end = ip_coords[dst_ip]
                    folium.PolyLine([start, end], color="red", weight=2, opacity=0.6).add_to(m)

            # GUNAKAN PATH ABSOLUT agar browser menemukan file
            map_file = os.path.abspath(f"sbs_interactive_map_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
            m.save(map_file)
        
            # Buka browser dengan path absolut
            webbrowser.open(f"file:///{map_file}")
        
            self._log_action(f"🗺️ Peta interaktif berhasil dibuat di: {map_file}")
        except Exception as e:
            self._log_action(f"❌ Gagal membuka peta interaktif: {e}")
            import traceback
            traceback.print_exc()  # Tampilkan error detail di terminal

    def export_database(self):
        rows = self.db.get_all_detections(limit=10000)

        # Export JSON
        file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[("JSON files", "*.json")])
        if file_path:
            data = []
            for row in rows:
                id_, ts, src_ip, dst_ip, port, cat, payload, rekom, country, city, lat, lon = row
                data.append({
                    "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": port,
                    "category": cat, "payload": payload, "rekomendasi": rekom,
                    "country": country, "city": city, "lat": lat, "lon": lon
                })
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self._log_action(f"Data diexport ke {file_path}")

        # Export CSV
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "category",
                                 "payload", "rekomendasi", "country", "city", "lat", "lon"])
                for row in rows:
                    writer.writerow(row[1:])  # skip id, mulai dari timestamp
            self._log_action(f"Data diexport ke {file_path}")

    def import_database(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for item in data:
                    self.db.insert_detection(
                        item["timestamp"], item["src_ip"], item.get("dst_ip"),
                        item.get("dst_port", 0), item["category"],
                        item["payload"], item["rekomendasi"]
                    )
                self.refresh_forensic_tab()
                self._log_action(f"Data berhasil diimport dari {file_path}")
            except Exception as e:
                self._log_action(f"Gagal import data: {e}")

    # ===== Selection handlers =====
    def on_table_select(self, event):
        selected = self.log_table.selection()
        if selected:
            values = self.log_table.item(selected[0], 'values')
            self.selected_ip = values[1]
            if self.selected_ip in self.blocked_ips:
                status = self.blocked_ips[self.selected_ip]["type"]
                if status == "isolate":
                    self.btn_isolate.config(state='disabled')
                    self.btn_release.config(state='normal')
                    self.btn_block.config(state='normal')
                    self.btn_unblock.config(state='disabled')
                else:
                    self.btn_isolate.config(state='normal')
                    self.btn_release.config(state='disabled')
                    self.btn_block.config(state='disabled')
                    self.btn_unblock.config(state='normal')
            else:
                self.btn_isolate.config(state='normal')
                self.btn_release.config(state='disabled')
                self.btn_block.config(state='normal')
                self.btn_unblock.config(state='disabled')
            self.btn_check.config(state='normal')
        else:
            self.selected_ip = None
            for btn in [self.btn_isolate, self.btn_release, self.btn_check, self.btn_block, self.btn_unblock]:
                btn.config(state='disabled')

    def on_forensic_table_select(self, event):
        selected = self.forensic_table.selection()
        if selected:
            values = self.forensic_table.item(selected[0], 'values')
            self.selected_ip = values[1]
            self.update_trace_table(self.selected_ip)
        else:
            self.selected_ip = None
            self.trace_table.delete(*self.trace_table.get_children())

    # ===== Honeypot Control =====
    def start_honeypot(self):
        self.log_monitor.insert('end', "[INFO] Menginisialisasi sistem pertahanan terintegrasi dasbor native...\n")
        try:
            self.worker_thread = InterceptorWorker()
            self.worker_thread.log_queue = self.log_queue
            self.worker_thread.start()
            self.update_status("RADAR AKTIF", "#00FF00")
            self.btn_start.config(state='disabled')
            self.btn_stop.config(state='normal')
        except Exception as e:
            self.update_status("GAGAL START", "#EF4444")
            self._log_action(f"[ERROR] Gagal menginisialisasi interceptor: {e}")

    def stop_honeypot(self):
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.stop()
            self.worker_thread.join(timeout=2)
            self.update_status("RADAR NONAKTIF", "#EF4444")
            self.btn_start.config(state='normal')
            self.btn_stop.config(state='disabled')
        else:
            self.update_status("RADAR NONAKTIF", "#EF4444")

    def update_status(self, text, color_hex):
        self.status_label.config(text=f"STATUS RADAR: {text}", fg=color_hex)


if __name__ == "__main__":
    root = tk.Tk()
    app = SBSApp(root)
    root.mainloop()
