#!/usr/bin/env python3

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

SCRIPT = "escaneame_esta.py"


class ScanGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.proc = None
        self.queue = queue.Queue()
        self.worker_thread = None
        self.reader_threads = []

        self.root.title("Escaneame_Esta — GUI")
        self.root.geometry("820x560")

        frame = ttk.Frame(root, padding=10)
        frame.pack(fill="x")

        ttk.Label(frame, text="CIDR:").grid(row=0, column=0, sticky="w")
        self.entry_cidr = ttk.Entry(frame, width=45)
        self.entry_cidr.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Archivo IPs:").grid(row=1, column=0, sticky="w")
        self.entry_file = ttk.Entry(frame, width=45)
        self.entry_file.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Buscar", command=self.select_file).grid(row=1, column=2)

        ttk.Label(frame, text="Prefijo salida:").grid(row=2, column=0, sticky="w")
        self.entry_out = ttk.Entry(frame, width=45)
        self.entry_out.insert(0, "hosts_escaneados")
        self.entry_out.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Workers:").grid(row=3, column=0, sticky="w")
        self.entry_workers = ttk.Entry(frame, width=12)
        self.entry_workers.insert(0, "50")
        self.entry_workers.grid(row=3, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(frame, text="Timeout:").grid(row=4, column=0, sticky="w")
        self.entry_timeout = ttk.Entry(frame, width=12)
        self.entry_timeout.insert(0, "1.0")
        self.entry_timeout.grid(row=4, column=1, sticky="w", padx=5, pady=5)

        self.var_skip_ping = tk.IntVar()
        self.var_no_arp = tk.IntVar()
        self.var_crypto = tk.IntVar()

        ttk.Checkbutton(frame, text="Saltar ping", variable=self.var_skip_ping).grid(row=5, column=0, sticky="w", pady=2)
        ttk.Checkbutton(frame, text="Desactivar ARP", variable=self.var_no_arp).grid(row=5, column=1, sticky="w", pady=2)
        ttk.Checkbutton(frame, text="Detección de minería", variable=self.var_crypto).grid(row=5, column=2, sticky="w", pady=2)

        btns = ttk.Frame(root, padding=10)
        btns.pack(fill="x")
        ttk.Button(btns, text="Iniciar escaneo", command=self.execute_scan).pack(side="left")
        ttk.Button(btns, text="Detener", command=self.stop_scan).pack(side="left", padx=8)
        ttk.Button(btns, text="Limpiar log", command=self.clear_log).pack(side="left", padx=8)

        self.progress = ttk.Progressbar(root, mode="indeterminate")
        self.progress.pack(fill="x", padx=10, pady=5)

        self.text_log = tk.Text(root, height=24)
        self.text_log.pack(fill="both", expand=True, padx=10, pady=10)

        self.root.after(50, self.process_queue)

    def select_file(self):
        path = filedialog.askopenfilename(filetypes=[("Texto", "*.txt"), ("Todos los archivos", "*")])
        if path:
            self.entry_file.delete(0, tk.END)
            self.entry_file.insert(0, path)

    def log(self, text: str):
        self.queue.put(text)

    def process_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                if item == "__SCAN_DONE__":
                    self.progress.stop()
                    self.proc = None
                    messagebox.showinfo("Éxito", "El escaneo ha finalizado.")
                    continue
                self.text_log.insert(tk.END, item)
                self.text_log.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(50, self.process_queue)

    def execute_scan(self):
        cidr = self.entry_cidr.get().strip()
        archivo = self.entry_file.get().strip()
        out = self.entry_out.get().strip() or "hosts_escaneados"

        if not cidr and not archivo:
            messagebox.showerror("Error", "Debes ingresar un CIDR o seleccionar un archivo.")
            return
        if not os.path.exists(SCRIPT):
            messagebox.showerror("Error", f"No se encontró el script: {SCRIPT}")
            return

        try:
            workers = int(self.entry_workers.get().strip())
            timeout = float(self.entry_timeout.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Workers y timeout deben ser numéricos.")
            return

        cmd = [sys.executable, "-u", SCRIPT]
        if cidr:
            cmd += ["--cidr", cidr]
        if archivo:
            cmd += ["--file", archivo]
        cmd += ["--out-prefix", out, "--workers", str(workers), "--timeout", str(timeout)]
        if self.var_skip_ping.get():
            cmd.append("--skip-ping")
        if self.var_no_arp.get():
            cmd.append("--no-arp")
        if self.var_crypto.get():
            cmd.append("--crypto-scan")

        self.clear_log()
        self.log("Ejecutando escaneo...\n")
        self.log(f"[DEBUG] {' '.join(cmd)}\n\n")
        self.progress.start(10)

        def run():
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

                def read_stream(stream, prefix=""):
                    try:
                        for line in iter(stream.readline, ""):
                            if not line:
                                break
                            self.log(f"{prefix}{line}")
                    finally:
                        try:
                            stream.close()
                        except Exception:
                            pass

                th_out = threading.Thread(target=read_stream, args=(self.proc.stdout, ""), daemon=True)
                th_err = threading.Thread(target=read_stream, args=(self.proc.stderr, "[ERROR] "), daemon=True)
                th_out.start()
                th_err.start()
                self.reader_threads = [th_out, th_err]

                self.proc.wait()
                th_out.join(timeout=1)
                th_err.join(timeout=1)
                self.queue.put("\n--- ESCANEO FINALIZADO ---\n")
                self.queue.put("__SCAN_DONE__")
            except Exception as e:
                self.queue.put(f"\n[ERROR] {e}\n")
                self.queue.put("__SCAN_DONE__")

        self.worker_thread = threading.Thread(target=run, daemon=True)
        self.worker_thread.start()

    def stop_scan(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.log("\n[INFO] Proceso detenido por el usuario.\n")
            except Exception as e:
                self.log(f"\n[ERROR] No se pudo detener el proceso: {e}\n")

    def clear_log(self):
        self.text_log.delete("1.0", tk.END)


def main():
    root = tk.Tk()
    ScanGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
