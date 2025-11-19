#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import os
import sys
import time


SCRIPT = "escaneame_esta.py"


def seleccionar_archivo():
    path = filedialog.askopenfilename(
        filetypes=[("Texto", "*.txt"), ("Todos los archivos", "*.*")]
    )
    if path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, path)


def ejecutar():
    cidr = entry_cidr.get().strip()
    archivo = entry_file.get().strip()
    out = entry_out.get().strip()

    if not cidr and not archivo:
        messagebox.showerror("Error", "Debes ingresar un CIDR o seleccionar un archivo.")
        return

    if not os.path.exists(SCRIPT):
        messagebox.showerror("Error", f"No se encontró el script: {SCRIPT}")
        return

    # Construir comando
    cmd = [sys.executable, SCRIPT]

    if cidr:
        cmd += ["--cidr", cidr]
    if archivo:
        cmd += ["--file", archivo]

    cmd += ["--out-prefix", out]

    if var_skip_ping.get() == 1:
        cmd.append("--skip-ping")
    if var_no_arp.get() == 1:
        cmd.append("--no-arp")
    if var_nmap.get() == 1:
        cmd.append("--use-nmap")

    text_log.delete("1.0", tk.END)
    text_log.insert(tk.END, "Ejecutando escaneo...\n")

    progress_bar["value"] = 0
    progress_bar.update()

    def run():
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            # Progreso como animación simple
            while proc.poll() is None:
                progress_bar.step(2)
                progress_bar.update()
                time.sleep(0.2)

            for line in proc.stdout or []:
                text_log.insert(tk.END, line)
                text_log.see(tk.END)

            progress_bar["value"] = 100
            progress_bar.update()

            text_log.insert(tk.END, "\n--- ESCANEO FINALIZADO ---\n")
            messagebox.showinfo("Éxito", "El escaneo ha finalizado.")

        except Exception as e:
            text_log.insert(tk.END, f"\n[ERROR] {e}\n")
            messagebox.showerror("Error", f"Ocurrió un error:\n{e}")

    threading.Thread(target=run, daemon=True).start()


# -------------------
# GUI
# -------------------
root = tk.Tk()
root.title("Escaneame_Esta — GUI Mejorada")
root.geometry("750x550")

frame = ttk.Frame(root, padding=10)
frame.pack(fill="x")

# CIDR
ttk.Label(frame, text="CIDR:").grid(row=0, column=0, sticky="w")
entry_cidr = ttk.Entry(frame, width=45)
entry_cidr.grid(row=0, column=1, padx=5, pady=5)

# Archivo
ttk.Label(frame, text="Archivo IPs:").grid(row=1, column=0, sticky="w")
entry_file = ttk.Entry(frame, width=45)
entry_file.grid(row=1, column=1, padx=5, pady=5)
ttk.Button(frame, text="Buscar", command=seleccionar_archivo).grid(row=1, column=2)

# Prefijo salida
ttk.Label(frame, text="Prefijo salida:").grid(row=2, column=0, sticky="w")
entry_out = ttk.Entry(frame, width=45)
entry_out.insert(0, "hosts_escaneados")
entry_out.grid(row=2, column=1, padx=5, pady=5)

# Opciones / Checkboxes
var_skip_ping = tk.IntVar()
var_no_arp = tk.IntVar()
var_nmap = tk.IntVar()

ttk.Checkbutton(frame, text="Saltar ping (--skip-ping)", variable=var_skip_ping).grid(row=3, column=0, sticky="w", pady=2)
ttk.Checkbutton(frame, text="Desactivar ARP (--no-arp)", variable=var_no_arp).grid(row=3, column=1, sticky="w", pady=2)
ttk.Checkbutton(frame, text="Usar Nmap (--use-nmap)", variable=var_nmap).grid(row=3, column=2, sticky="w", pady=2)

# Botón Escaneo
ttk.Button(frame, text="Iniciar Escaneo", command=ejecutar).grid(
    row=4, column=0, columnspan=3, pady=10
)

# Barra de progreso
progress_bar = ttk.Progressbar(root, mode="indeterminate")
progress_bar.pack(fill="x", padx=10, pady=5)

# Log
text_log = tk.Text(root, height=20)
text_log.pack(fill="both", expand=True, padx=10, pady=10)

root.mainloop()
