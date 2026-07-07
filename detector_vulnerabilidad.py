
from pathlib import Path
out = Path('output')
out.mkdir(exist_ok=True)

scanner = r'''#!/usr/bin/env python3
"""
escaneame_esta.py v3.0
Escaneo de IPs con heurísticas, salida JSON/CSV y detección opcional de indicios de minería.
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from tqdm import tqdm
except Exception:
    tqdm = None

DEFAULT_OUT_PREFIX = "hosts_escaneados"
DEFAULT_PORTS = [22, 80, 443, 139, 445]
DEFAULT_WORKERS = 50
DEFAULT_TIMEOUT = 1.0
DEFAULT_RETRIES = 1
DEFAULT_CRYPTO_PORTS = [3333, 4444, 5555, 7777, 8332, 8333, 9333, 14444, 33333, 45560, 55555, 6060, 8888]

OUI_MAP = {
    "00:11:22": "DELL",
    "00:15:5D": "MICROSOFT",
    "00:1A:2B": "HP",
    "00:09:5B": "CISCO",
    "44:65:0D": "APPLE",
    "00:0C:29": "VMWARE",
    "F4:5C:89": "HUAWEI",
}

ARP_CACHE: Dict[str, Optional[str]] = {}


@dataclass
class ScanResult:
    ip: str
    reachable: bool = False
    rdns: str = ""
    netbios: str = ""
    mac: str = ""
    vendor: str = ""
    device_type: str = ""
    banners: Dict[int, str] = field(default_factory=dict)
    crypto_suspicion: bool = False
    crypto_ports: List[int] = field(default_factory=list)
    crypto_details: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict:
        data = asdict(self)
        data["banners"] = {str(k): v for k, v in self.banners.items()}
        return data


def run_cmd(cmd: List[str], timeout: float = 3.0) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)


def ping_ip(ip: str, timeout: float = 1.0) -> bool:
    plat = platform.system().lower()
    if "windows" in plat:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    rc, _, _ = run_cmd(cmd, timeout=timeout + 1)
    return rc == 0


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def netbios_nbtscan(ip: str) -> str:
    nbtscan_path = shutil.which("nbtscan")
    if not nbtscan_path:
        return ""
    rc, out, _ = run_cmd([nbtscan_path, "-s:", ip], timeout=3)
    if rc != 0:
        return ""
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("IP") or line.startswith("Scanning"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 2:
            return parts[1].split("<")[0]
    return ""


def netbios_windows(ip: str) -> str:
    try:
        proc = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3)
        for line in proc.stdout.splitlines():
            if "<00>" in line:
                return line.split()[0].strip()
    except Exception:
        pass
    return ""


def get_netbios_name(ip: str) -> str:
    plat = platform.system().lower()
    if "windows" in plat:
        nb = netbios_windows(ip)
        if nb:
            return nb
    return netbios_nbtscan(ip)


def get_mac_from_arp(ip: str) -> str:
    if ip in ARP_CACHE:
        return ARP_CACHE[ip] or ""

    mac = ""
    plat = platform.system().lower()

    if "linux" in plat:
        _, out, _ = run_cmd(["ip", "neigh", "show", ip], timeout=1)
        m = re.search(r"([0-9a-fA-F:]{17})", out)
        if m:
            mac = m.group(1).lower()

    if not mac:
        _, out, _ = run_cmd(["arp", "-n", ip], timeout=1)
        m = re.search(r"([0-9a-fA-F:]{17})", out)
        if m:
            mac = m.group(1).lower()

    if not mac and shutil.which("arping"):
        run_cmd(["arping", "-c", "1", "-w", "1", ip], timeout=2)
        _, out2, _ = run_cmd(["arp", "-n", ip], timeout=1)
        m = re.search(r"([0-9a-fA-F:]{17})", out2)
        if m:
            mac = m.group(1).lower()

    ARP_CACHE[ip] = mac or None
    return mac


def guess_vendor(mac: str) -> str:
    if not mac:
        return ""
    prefix = mac.upper()[0:8]
    return OUI_MAP.get(prefix, "")


def probe_banner(ip: str, port: int, timeout: float) -> Tuple[bool, str]:
    try:
        if port == 443:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ss:
                    subj_str = ""
                    try:
                        cert = ss.getpeercert()
                        subject = cert.get("subject", ())
                        subj_str = " ".join("=".join(x) for part in subject for x in part)
                    except Exception:
                        pass
                    first = ""
                    try:
                        req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                        ss.sendall(req)
                        data = ss.recv(1024)
                        first = data.decode(errors="ignore").splitlines()[0] if data else ""
                    except Exception:
                        pass
                    return True, f"cert={subj_str};resp={first}"

        if port == 80:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                s.sendall(req)
                data = s.recv(2048).decode(errors="ignore")
                status = data.splitlines()[0] if data else ""
                m = re.search(r"Server:\s*(.+)", data, flags=re.I)
                server = m.group(1).strip() if m else ""
                return True, f"{status} | Server: {server}".strip()

        if port == 22:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                return True, s.recv(256).decode(errors="ignore").strip()

        with socket.create_connection((ip, port), timeout=timeout) as s:
            try:
                data = s.recv(512).decode(errors="ignore").strip()
            except Exception:
                data = ""
            return True, data
    except Exception:
        return False, ""


def classify_device(rdns: str, netbios: str, banners: Dict[int, str], vendor: str) -> str:
    banners_text = " ".join(banners.values()).lower()
    rdns_l = (rdns or "").lower()
    nb_l = (netbios or "").lower()
    vendor_l = (vendor or "").lower()

    if any(x in rdns_l for x in ["printer", "print", "impresora"]):
        return "Impresora/Escáner"
    if any(x in nb_l for x in ["printer", "print"]):
        return "Impresora/Escáner"
    if any(x in banners_text for x in ["hp", "xerox", "epson", "printer"]):
        return "Impresora/Escáner"
    if vendor and any(v in vendor_l for v in ["cisco", "huawei", "juniper"]):
        return "Equipo de red (router/switch)"
    if any(p in banners for p in [80, 443]):
        return "Servidor Web"
    if 22 in banners and "openssh" in banners[22].lower():
        return "Servidor Linux/UNIX"
    if any(p in banners for p in [139, 445]):
        return "Equipo Windows (SMB)"
    if vendor and "apple" in vendor_l:
        return "Apple (Mac/iOS)"
    return "Equipo (genérico/no identificado)"


def check_crypto_ports(ip: str, ports: List[int], timeout: float = 1.0) -> Dict:
    details = []
    open_ports = []
    for port in ports:
        ok, banner = probe_banner(ip, port, timeout)
        if ok:
            open_ports.append(port)
            details.append({"port": port, "type": "Posible servicio asociado a minería", "banner": banner})
    return {
        "has_crypto": bool(open_ports),
        "open_ports": open_ports,
        "details": details,
    }


def scan_ip(ip: str, ports: List[int], timeout: float, retries: int, skip_ping: bool = False, try_arp: bool = True, crypto_scan: bool = False, crypto_ports: Optional[List[int]] = None) -> Dict:
    result = ScanResult(ip=ip)

    if skip_ping:
        result.reachable = True
    else:
        result.reachable = ping_ip(ip, timeout)

    result.rdns = reverse_dns(ip)
    result.netbios = get_netbios_name(ip)

    if try_arp:
        result.mac = get_mac_from_arp(ip)
        result.vendor = guess_vendor(result.mac)

    for p in ports:
        ok = False
        banner = ""
        for _ in range(max(1, retries)):
            ok, banner = probe_banner(ip, p, timeout)
            if ok:
                break
        if ok:
            result.banners[p] = banner

    if crypto_scan:
        crypto = check_crypto_ports(ip, crypto_ports or DEFAULT_CRYPTO_PORTS, timeout)
        result.crypto_suspicion = crypto["has_crypto"]
        result.crypto_ports = crypto["open_ports"]
        result.crypto_details = crypto["details"]

    result.device_type = classify_device(result.rdns, result.netbios, result.banners, result.vendor)
    return result.to_dict()


def load_ips_from_file(path: str) -> List[str]:
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def generate_ips_from_cidr(cidr: str) -> List[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in net.hosts()]


def save_csv(results: List[Dict], out_prefix: str) -> str:
    path = f"{out_prefix}.csv"
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "reachable", "reverse_dns", "netbios", "mac", "vendor", "device_type", "crypto_suspicion", "crypto_ports", "banners"])
        for r in results:
            banners = ";".join([f"{p}={str(banner)[:200]}" for p, banner in r.get("banners", {}).items()])
            writer.writerow([
                r.get("ip", ""),
                r.get("reachable", False),
                r.get("rdns", ""),
                r.get("netbios", ""),
                r.get("mac", ""),
                r.get("vendor", ""),
                r.get("device_type", ""),
                r.get("crypto_suspicion", False),
                ",".join(map(str, r.get("crypto_ports", []))),
                banners,
            ])
    return path


def save_json(results: List[Dict], out_prefix: str) -> str:
    path = f"{out_prefix}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    return path


def save_summary(results: List[Dict], out_prefix: str) -> str:
    path = f"resumen_{out_prefix}.txt"
    types_count = Counter(r.get("device_type", "") for r in results)
    crypto_count = sum(1 for r in results if r.get("crypto_suspicion"))
    with open(path, "w", encoding="utf-8") as f:
        f.write("Resumen del escaneo\n\n")
        f.write(f"Total IPs escaneadas: {len(results)}\n")
        f.write(f"Hosts con indicios de minería: {crypto_count}\n\n")
        for t, c in types_count.most_common():
            f.write(f"{t}: {c}\n")
    return path


def parse_ports(value: str) -> List[int]:
    ports = []
    for part in value.split(","):
        part = part.strip()
        if part:
            ports.append(int(part))
    return ports


def main() -> int:
    parser = argparse.ArgumentParser(description="Escaneo de IPs con heurísticas y progresos")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cidr")
    group.add_argument("--file")
    parser.add_argument("--out-prefix", default=DEFAULT_OUT_PREFIX)
    parser.add_argument("--ports", default=",".join(str(x) for x in DEFAULT_PORTS))
    parser.add_argument("--crypto-ports", default=",".join(str(x) for x in DEFAULT_CRYPTO_PORTS))
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--no-arp", action="store_true")
    parser.add_argument("--skip-ping", action="store_true")
    parser.add_argument("--crypto-scan", action="store_true")
    args = parser.parse_args()

    if args.cidr:
        print(f"[+] Generando IPs desde CIDR {args.cidr}")
        ips = generate_ips_from_cidr(args.cidr)
    else:
        print(f"[+] Leyendo IPs desde archivo {args.file}")
        ips = load_ips_from_file(args.file)

    ports = parse_ports(args.ports)
    crypto_ports = parse_ports(args.crypto_ports)

    print(f"[+] Total IPs: {len(ips)} | Puertos: {ports} | Workers: {args.workers}")
    if args.crypto_scan:
        print(f"[+] Detección adicional activada en puertos: {crypto_ports}")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {
            executor.submit(
                scan_ip,
                ip,
                ports,
                args.timeout,
                args.retries,
                args.skip_ping,
                not args.no_arp,
                args.crypto_scan,
                crypto_ports,
            ): ip for ip in ips
        }

        iterator = concurrent.futures.as_completed(futures)
        if tqdm:
            iterator = tqdm(iterator, total=len(futures), desc="Escaneando")

        for fut in iterator:
            ip = futures[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                print(f"[ERROR] Falló {ip}: {e}")

    print("Guardando archivos...")
    csv_path = save_csv(results, args.out_prefix)
    json_path = save_json(results, args.out_prefix)
    summary_path = save_summary(results, args.out_prefix)

    print(f"[+] Guardado CSV: {csv_path}")
    print(f"[+] Guardado JSON: {json_path}")
    print(f"[+] Guardado resumen: {summary_path}")
    print("ESCANEO COMPLETO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

gui = r'''#!/usr/bin/env python3
"""
gui_escaneame.py
Interfaz Tkinter para ejecutar escaneos sin bloquear la GUI.
"""

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
'''

readme = r'''# Escaneame_Esta

Proyecto de escaneo local de red con heurísticas de identificación, salida CSV/JSON y GUI Tkinter.

## Archivos
- `escaneame_esta.py`: escáner principal.
- `gui_escaneame.py`: interfaz gráfica.

## Uso CLI
```bash
python escaneame_esta.py --cidr 192.168.1.0/24
python escaneame_esta.py --file ips.txt --out-prefix mi_red --crypto-scan
```

## Uso GUI
```bash
python gui_escaneame.py
```

## Notas
- La detección de minería es heurística y solo marca indicios.
- La GUI usa una cola para evitar actualizar Tkinter desde hilos secundarios.
- Puedes ajustar `--workers`, `--timeout`, `--skip-ping`, `--no-arp` y `--crypto-scan`.
'''

(out / 'escaneame_esta.py').write_text(scanner, encoding='utf-8')
(out / 'gui_escaneame.py').write_text(gui, encoding='utf-8')
(out / 'README.md').write_text(readme, encoding='utf-8')

print((out / 'escaneame_esta.py').as_posix())
print((out / 'gui_escaneame.py').as_posix())
print((out / 'README.md').as_posix())
