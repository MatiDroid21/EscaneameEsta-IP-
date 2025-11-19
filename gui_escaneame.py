#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import os
import sys
import time


SCRIPT = "escaneame_esta.py"


# ------------------------------
# Selección de archivo
# ------------------------------
def seleccionar_archivo():
    path = filedialog.askopenfilename(
        filetypes=[("Texto", "*.txt"), ("Todos los archivos", "*.*")]
    )
    if path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, path)


# ------------------------------
# EJECUCIÓN DEL ESCANEO
# ------------------------------
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

    # Construcción del comando
    cmd = [sys.executable, "-u", SCRIPT]

    if cidr:
        cmd += ["--cidr", cidr]
    if archivo:
        cmd += ["--file", archivo]

    cmd += ["--out-prefix", out]

    if var_skip_ping.get() == 1:
        cmd.append("--skip-ping")
    if var_no_arp.get() == 1:
        cmd.append("--no-arp")

    # Limpiar log
    text_log.delete("1.0", tk.END)
    text_log.insert(tk.END, "Ejecutando escaneo...\n")

    # Barra indeterminada
    progress_bar.start(10)

    # --------------------------
    # Hilo de ejecución
    # --------------------------
    def run():
        try:
            text_log.insert(tk.END, f"[DEBUG] Ejecutando:\n{' '.join(cmd)}\n\n")

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            # --- Lectores concurrentes ---
            def leer_stdout():
                for line in proc.stdout:
                    text_log.insert(tk.END, line)
                    text_log.see(tk.END)

            def leer_stderr():
                for line in proc.stderr:
                    text_log.insert(tk.END, f"[ERROR] {line}")
                    text_log.see(tk.END)

            th_out = threading.Thread(target=leer_stdout, daemon=True)
            th_err = threading.Thread(target=leer_stderr, daemon=True)

            th_out.start()
            th_err.start()

            # Esperar fin del proceso
            proc.wait()

            progress_bar.stop()

            text_log.insert(tk.END, "\n--- ESCANEO FINALIZADO ---\n")
            text_log.see(tk.END)

            messagebox.showinfo("Éxito", "El escaneo ha finalizado.")

        except Exception as e:
            progress_bar.stop()
            text_log.insert(tk.END, f"\n[ERROR] {e}\n")
            messagebox.showerror("Error", f"Ocurrió un error:\n{e}")

    threading.Thread(target=run, daemon=True).start()


# ------------------------------
# GUI
# ------------------------------
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

# Opciones
var_skip_ping = tk.IntVar()
var_no_arp = tk.IntVar()

ttk.Checkbutton(frame, text="Saltar ping (--skip-ping)", variable=var_skip_ping)\
    .grid(row=3, column=0, sticky="w", pady=2)
ttk.Checkbutton(frame, text="Desactivar ARP (--no-arp)", variable=var_no_arp)\
    .grid(row=3, column=1, sticky="w", pady=2)

# Botón
ttk.Button(frame, text="Iniciar Escaneo", command=ejecutar)\
    .grid(row=4, column=0, columnspan=3, pady=10)

# Progreso
progress_bar = ttk.Progressbar(root, mode="indeterminate")
progress_bar.pack(fill="x", padx=10, pady=5)

# Log
text_log = tk.Text(root, height=20)
text_log.pack(fill="both", expand=True, padx=10, pady=10)

root.mainloop()
