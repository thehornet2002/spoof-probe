import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from .iplist import parse_ip_file
from .runner import ProbeRunner


class SpoofProbeGUI(tk.Tk):
    """Modern Tkinter GUI for Spoof Probe."""

    def __init__(self):
        super().__init__()
        self.title("Spoof Probe - Multi-Protocol IP Spoof Tester (TCP, UDP, ICMP)")
        self.geometry("820x680")
        self.minsize(720, 560)

        # Apply clean theme
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        self.runner: Optional[ProbeRunner] = None
        self.stop_requested = False
        self.active_thread: Optional[threading.Thread] = None

        self._build_ui()

    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tab_sender = ttk.Frame(notebook)
        self.tab_receiver = ttk.Frame(notebook)

        notebook.add(self.tab_sender, text="  Sender Mode (ارسال پکت‌های جعلی)  ")
        notebook.add(self.tab_receiver, text="  Receiver Mode (دریافت و فیلتر)  ")

        self._build_sender_tab(self.tab_sender)
        self._build_receiver_tab(self.tab_receiver)

        # Status Bar
        self.lbl_status = ttk.Label(self, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.lbl_status.pack(side=tk.BOTTOM, fill=tk.X)

    # ═══════════════════════════════════════════════════════════
    # SENDER TAB
    # ═══════════════════════════════════════════════════════════

    def _build_sender_tab(self, parent):
        frame = ttk.LabelFrame(parent, text="Sender Settings", padding=12)
        frame.pack(fill=tk.X, padx=10, pady=10)

        # Destination IP & Port
        row1 = ttk.Frame(frame)
        row1.pack(fill=tk.X, pady=4)
        ttk.Label(row1, text="Destination IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.ent_dst_ip = ttk.Entry(row1, width=20)
        self.ent_dst_ip.pack(side=tk.LEFT, padx=(0, 15))

        ttk.Label(row1, text="Port:").pack(side=tk.LEFT, padx=(0, 5))
        self.ent_dst_port = ttk.Entry(row1, width=8)
        self.ent_dst_port.insert(0, "8090")
        self.ent_dst_port.pack(side=tk.LEFT)

        # Source IP List
        row2 = ttk.Frame(frame)
        row2.pack(fill=tk.X, pady=4)
        ttk.Label(row2, text="Source IP List:").pack(side=tk.LEFT, padx=(0, 5))
        self.ent_send_file = ttk.Entry(row2)
        self.ent_send_file.insert(0, "ips.txt")
        self.ent_send_file.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(row2, text="Browse...", command=lambda: self._browse_file(self.ent_send_file)).pack(side=tk.LEFT)

        # Protocols
        row3 = ttk.Frame(frame)
        row3.pack(fill=tk.X, pady=6)
        ttk.Label(row3, text="Protocols:").pack(side=tk.LEFT, padx=(0, 10))
        self.var_send_tcp = tk.BooleanVar(value=True)
        self.var_send_udp = tk.BooleanVar(value=True)
        self.var_send_icmp = tk.BooleanVar(value=True)

        ttk.Checkbutton(row3, text="TCP SYN", variable=self.var_send_tcp).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(row3, text="UDP", variable=self.var_send_udp).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(row3, text="ICMP Ping", variable=self.var_send_icmp).pack(side=tk.LEFT, padx=5)

        # Parameters
        row4 = ttk.Frame(frame)
        row4.pack(fill=tk.X, pady=4)
        ttk.Label(row4, text="Packets / IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.spn_send_count = ttk.Spinbox(row4, from_=1, to=10, width=5)
        self.spn_send_count.set("2")
        self.spn_send_count.pack(side=tk.LEFT, padx=(0, 15))

        ttk.Label(row4, text="Delay (ms):").pack(side=tk.LEFT, padx=(0, 5))
        self.ent_send_delay = ttk.Entry(row4, width=6)
        self.ent_send_delay.insert(0, "0.2")
        self.ent_send_delay.pack(side=tk.LEFT, padx=(0, 15))

        # Start / Stop Buttons
        row5 = ttk.Frame(parent)
        row5.pack(fill=tk.X, padx=10, pady=5)
        self.btn_send_start = ttk.Button(row5, text="▶ Start Sending", command=self._start_sender)
        self.btn_send_start.pack(side=tk.LEFT, padx=(0, 10))
        self.btn_send_stop = ttk.Button(row5, text="■ Stop", state=tk.DISABLED, command=self._stop_test)
        self.btn_send_stop.pack(side=tk.LEFT)

        self.prog_send = ttk.Progressbar(parent, orient=tk.HORIZONTAL, mode="determinate")
        self.prog_send.pack(fill=tk.X, padx=10, pady=5)

        # Log Output
        self.txt_send_log = tk.Text(parent, wrap=tk.WORD, height=14)
        self.txt_send_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # ═══════════════════════════════════════════════════════════
    # RECEIVER TAB
    # ═══════════════════════════════════════════════════════════

    def _build_receiver_tab(self, parent):
        frame = ttk.LabelFrame(parent, text="Receiver Settings", padding=12)
        frame.pack(fill=tk.X, padx=10, pady=10)

        # Listen Port
        row1 = ttk.Frame(frame)
        row1.pack(fill=tk.X, pady=4)
        ttk.Label(row1, text="Listen / Filter Port:").pack(side=tk.LEFT, padx=(0, 5))
        self.ent_recv_port = ttk.Entry(row1, width=8)
        self.ent_recv_port.insert(0, "8090")
        self.ent_recv_port.pack(side=tk.LEFT, padx=(0, 15))

        ttk.Label(row1, text="Timeout (sec):").pack(side=tk.LEFT, padx=(0, 5))
        self.ent_recv_timeout = ttk.Entry(row1, width=6)
        self.ent_recv_timeout.insert(0, "120")
        self.ent_recv_timeout.pack(side=tk.LEFT, padx=(0, 15))

        ttk.Label(row1, text="Max Allowed Loss (%):").pack(side=tk.LEFT, padx=(0, 5))
        self.ent_recv_loss = ttk.Entry(row1, width=6)
        self.ent_recv_loss.insert(0, "50.0")
        self.ent_recv_loss.pack(side=tk.LEFT)

        # Expected Source IP List
        row2 = ttk.Frame(frame)
        row2.pack(fill=tk.X, pady=4)
        ttk.Label(row2, text="Expected IP List:").pack(side=tk.LEFT, padx=(0, 5))
        self.ent_recv_file = ttk.Entry(row2)
        self.ent_recv_file.insert(0, "ips.txt")
        self.ent_recv_file.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(row2, text="Browse...", command=lambda: self._browse_file(self.ent_recv_file)).pack(side=tk.LEFT)

        # Output file
        row3 = ttk.Frame(frame)
        row3.pack(fill=tk.X, pady=4)
        ttk.Label(row3, text="Passed IPs Output:").pack(side=tk.LEFT, padx=(0, 5))
        self.ent_recv_out = ttk.Entry(row3)
        self.ent_recv_out.insert(0, "passed_ips.txt")
        self.ent_recv_out.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        # Protocols
        row4 = ttk.Frame(frame)
        row4.pack(fill=tk.X, pady=6)
        ttk.Label(row4, text="Protocols:").pack(side=tk.LEFT, padx=(0, 10))
        self.var_recv_tcp = tk.BooleanVar(value=True)
        self.var_recv_udp = tk.BooleanVar(value=True)
        self.var_recv_icmp = tk.BooleanVar(value=True)

        ttk.Checkbutton(row4, text="TCP SYN", variable=self.var_recv_tcp).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(row4, text="UDP", variable=self.var_recv_udp).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(row4, text="ICMP Ping", variable=self.var_recv_icmp).pack(side=tk.LEFT, padx=5)

        # Start / Stop Buttons
        row5 = ttk.Frame(parent)
        row5.pack(fill=tk.X, padx=10, pady=5)
        self.btn_recv_start = ttk.Button(row5, text="▶ Start Listening", command=self._start_receiver)
        self.btn_recv_start.pack(side=tk.LEFT, padx=(0, 10))
        self.btn_recv_stop = ttk.Button(row5, text="■ Stop", state=tk.DISABLED, command=self._stop_test)
        self.btn_recv_stop.pack(side=tk.LEFT)

        self.prog_recv = ttk.Progressbar(parent, orient=tk.HORIZONTAL, mode="determinate")
        self.prog_recv.pack(fill=tk.X, padx=10, pady=5)

        # Log Output
        self.txt_recv_log = tk.Text(parent, wrap=tk.WORD, height=14)
        self.txt_recv_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # ═══════════════════════════════════════════════════════════
    # Logic
    # ═══════════════════════════════════════════════════════════

    def _browse_file(self, entry):
        filename = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if filename:
            entry.delete(0, tk.END)
            entry.insert(0, filename)

    def _log_sender(self, msg: str):
        self.txt_send_log.insert(tk.END, msg + "\n")
        self.txt_send_log.see(tk.END)

    def _log_receiver(self, msg: str):
        self.txt_recv_log.insert(tk.END, msg + "\n")
        self.txt_recv_log.see(tk.END)

    def _get_protocols(self, is_sender: bool) -> str:
        tcp = self.var_send_tcp.get() if is_sender else self.var_recv_tcp.get()
        udp = self.var_send_udp.get() if is_sender else self.var_recv_udp.get()
        icmp = self.var_send_icmp.get() if is_sender else self.var_recv_icmp.get()

        if tcp and udp and icmp:
            return "all"
        elif tcp and not udp and not icmp:
            return "tcp"
        elif udp and not tcp and not icmp:
            return "udp"
        elif icmp and not tcp and not udp:
            return "icmp"
        return "all"

    def _stop_test(self):
        self.stop_requested = True
        self.lbl_status.config(text="Stopping test...")

    def _start_sender(self):
        dst_ip = self.ent_dst_ip.get().strip()
        if not dst_ip:
            messagebox.showerror("Error", "Destination IP is required.")
            return

        src_file = self.ent_send_file.get().strip()
        if not os.path.exists(src_file):
            messagebox.showerror("Error", f"Source IP file not found: {src_file}")
            return

        try:
            dst_port = int(self.ent_dst_port.get().strip())
            count = int(self.spn_send_count.get().strip())
            delay_ms = float(self.ent_send_delay.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid numeric values for Port, Count, or Delay.")
            return

        proto = self._get_protocols(is_sender=True)
        self.txt_send_log.delete("1.0", tk.END)
        self.btn_send_start.config(state=tk.DISABLED)
        self.btn_send_stop.config(state=tk.NORMAL)
        self.lbl_status.config(text="Running Sender...")
        self.stop_requested = False

        def worker():
            try:
                self._log_sender(f"[*] Parsing IP ranges from {src_file} ...")
                ranges = parse_ip_file(src_file)
                self._log_sender(f"[*] Loaded {ranges.total} total source IPs")

                runner = ProbeRunner()
                runner.run_sender(
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=proto,
                    ranges=ranges,
                    packet_count=count,
                    delay_ms=delay_ms,
                )
                self._log_sender("[✓] Sender finished successfully.")
            except Exception as e:
                self._log_sender(f"[!] Error: {e}")
            finally:
                self.btn_send_start.config(state=tk.NORMAL)
                self.btn_send_stop.config(state=tk.DISABLED)
                self.lbl_status.config(text="Ready")

        self.active_thread = threading.Thread(target=worker, daemon=True)
        self.active_thread.start()

    def _start_receiver(self):
        src_file = self.ent_recv_file.get().strip()
        if not os.path.exists(src_file):
            messagebox.showerror("Error", f"Expected IP file not found: {src_file}")
            return

        try:
            port = int(self.ent_recv_port.get().strip())
            timeout = int(self.ent_recv_timeout.get().strip())
            max_loss = float(self.ent_recv_loss.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid numeric values for Port, Timeout, or Max Loss.")
            return

        out_file = self.ent_recv_out.get().strip()
        proto = self._get_protocols(is_sender=False)
        self.txt_recv_log.delete("1.0", tk.END)
        self.btn_recv_start.config(state=tk.DISABLED)
        self.btn_recv_stop.config(state=tk.NORMAL)
        self.lbl_status.config(text="Running Receiver...")
        self.stop_requested = False

        def worker():
            try:
                self._log_receiver(f"[*] Parsing expected IP ranges from {src_file} ...")
                ranges = parse_ip_file(src_file)
                self._log_receiver(f"[*] Loaded {ranges.total} total expected IPs")

                runner = ProbeRunner()
                runner.run_receiver(
                    filter_port=port,
                    protocol=proto,
                    ranges=ranges,
                    packet_count=2,
                    max_loss_pct=max_loss,
                    timeout=timeout,
                    output_file=out_file,
                )
                self._log_receiver(f"[✓] Receiver test finished. Results saved to {out_file}")
            except Exception as e:
                self._log_receiver(f"[!] Error: {e}")
            finally:
                self.btn_recv_start.config(state=tk.NORMAL)
                self.btn_recv_stop.config(state=tk.DISABLED)
                self.lbl_status.config(text="Ready")

        self.active_thread = threading.Thread(target=worker, daemon=True)
        self.active_thread.start()


def run_gui():
    app = SpoofProbeGUI()
    app.mainloop()
