
#!/usr/bin/env python3

"""
escaneame_esta.py v.2.1 — Escaneo de IPs con heurística de identificación
Novedades:
 - CLI: --ports, --retries, --timeout, --workers, --arp, --use-nmap, --skip-ping
 - Mejor banner grabbing (HTTP/1.1, SSH, TLS cert subject)
 - Fallbacks y cachés (ARP, NBTSCAN)
 - Salida CSV robusta (csv module), JSON y resumen
 - Progreso con tqdm si está disponible
 - Clasificación ampliada

Autor: MatiDroid21
Descripción:
  Escanea un conjunto de direcciones IP (desde un CIDR o desde un archivo)
  y produce un análisis heurístico por host: alcance (ping), reverse DNS,
  nombre NetBIOS (si está disponible), MAC desde la tabla ARP local,
  intentos de conexión TCP a puertos comunes y clasificación del tipo de
  dispositivo (impresora, servidor web, equipo Windows, etc.).

Características principales:
  - Soporta entrada por rango CIDR (ej. 192.168.1.0/24) o por archivo de IPs.
  - Usa ping para determinar alcance y consulta DNS inversa.
  - Intenta obtener nombre NetBIOS (nbtstat/nbtscan) y MAC desde ARP.
  - Prueba puertos TCP comunes (22, 80, 443, 139, 445) y recoge banners.
  - Clasifica dispositivos con reglas heurísticas (banners, nombres, vendor OUI).
  - Salida en CSV, JSON y un resumen TXT con agregados útiles.

Uso:
  python escaneame_esta.py --cidr 192.168.1.0/24
  python escaneame_esta.py --file ips.txt --out-prefix mi_red

Salida generada (prefijo `--out-prefix`, por defecto "hosts_escaneados"):
  - <out-prefix>.csv       : CSV con los detalles por host
  - <out-prefix>.json      : JSON con los resultados completos (estructura legible)
  - resumen_<out-prefix>.txt : Resumen humano con conteos y notas

Advertencias y recomendaciones:
  - Requiere permisos para ejecutar herramientas de red y acceder a la tabla ARP.
  - Algunas funcionalidades (nbtscan, nbtstat) dependen de utilidades externas.
  - La identificación es heurística: puede haber falsos positivos/negativos.
  - Asegúrate de tener autorización para escanear la red objetivo.
"""

import argparse
import ipaddress
import platform
import subprocess
import socket
import concurrent.futures
import time
import shutil
import re
import json
import ssl
import csv
import sys
from typing import Optional, Dict, List, Tuple
from collections import defaultdict

import argparse
import ipaddress
import platform
import subprocess
import socket
import concurrent.futures
import time
import shutil
import re
import json
import ssl
import csv
import sys
from typing import Optional, Dict, List, Tuple
from collections import defaultdict

# Opcional: tqdm para barra de progreso en consola
try:
    from tqdm import tqdm
except Exception:
    tqdm = None

# Constantes
DEFAULT_OUT_PREFIX = "hosts_escaneados"
DEFAULT_PORTS = [22, 80, 443, 139, 445]
DEFAULT_WORKERS = 50
DEFAULT_TIMEOUT = 1.0
DEFAULT_RETRIES = 1

# OUI MAP
OUI_MAP = {
    "00:11:22": "DELL",
    "00:15:5D": "MICROSOFT",
    "00:1A:2B": "HP",
    "00:09:5B": "CISCO",
    "44:65:0D": "APPLE",
    "00:0C:29": "VMWARE",
    "F4:5C:89": "HUAWEI",
}

# -----------------------
# Funciones auxiliares
# -----------------------
def run_cmd(cmd: List[str], timeout: float = 3.0):
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
        cmd = ["ping", "-c", "1", "-W", str(int(max(1, timeout))), ip]
    rc, out, err = run_cmd(cmd, timeout=timeout + 1)
    return rc == 0

def reverse_dns(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

# -----------------------
# NetBIOS
# -----------------------
def netbios_nbtscan(ip: str):
    nbtscan_path = shutil.which("nbtscan")
    if not nbtscan_path:
        return None
    rc, out, err = run_cmd([nbtscan_path, "-s:", ip], timeout=3)
    if rc != 0:
        return None
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("IP") or line.startswith("Scanning"):
            continue
        parts = re.split(r'\s+', line)
        if len(parts) >= 2:
            name_field = parts[1]
            name = name_field.split("<")[0]
            return name
    return None

def netbios_windows(ip: str):
    try:
        proc = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3)
        for line in proc.stdout.splitlines():
            if "<00>" in line:
                return line.split()[0].strip()
    except:
        return None

def get_netbios_name(ip: str):
    plat = platform.system().lower()
    if "windows" in plat:
        nb = netbios_windows(ip)
        if nb:
            return nb
    return netbios_nbtscan(ip)

# -----------------------
# ARP
# -----------------------
arp_cache = {}

def get_mac_from_arp(ip: str):
    if ip in arp_cache:
        return arp_cache[ip]

    mac = None
    plat = platform.system().lower()

    if "linux" in plat:
        rc, out, err = run_cmd(["ip", "neigh", "show", ip], timeout=1)
        m = re.search(r"([0-9a-fA-F:]{17})", out)
        if m:
            mac = m.group(1).lower()

    if not mac:
        rc, out, err = run_cmd(["arp", "-n", ip], timeout=1)
        m = re.search(r"([0-9a-fA-F:]{17})", out)
        if m:
            mac = m.group(1).lower()

    if not mac and shutil.which("arping"):
        rc, out, err = run_cmd(["arping", "-c", "1", "-w", "1", ip], timeout=2)
        rc2, out2, err2 = run_cmd(["arp", "-n", ip], timeout=1)
        m = re.search(r"([0-9a-fA-F:]{17})", out2)
        if m:
            mac = m.group(1).lower()

    arp_cache[ip] = mac
    return mac

def guess_vendor(mac):
    if not mac:
        return None
    prefix = mac.upper()[0:8]
    return OUI_MAP.get(prefix)

# -----------------------
# Banner grabbing
# -----------------------
def probe_banner(ip: str, port: int, timeout: float):
    try:
        if port == 443:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ss:
                    try:
                        cert = ss.getpeercert()
                        subject = cert.get("subject", ())
                        subj_str = " ".join("=".join(x) for part in subject for x in part)
                    except:
                        subj_str = ""

                    try:
                        req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                        ss.sendall(req)
                        data = ss.recv(1024)
                        first = data.decode(errors="ignore").splitlines()[0] if data else ""
                    except:
                        first = ""

                    return True, f"cert={subj_str};resp={first}"

        elif port == 80:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                s.sendall(req)
                data = s.recv(2048).decode(errors="ignore")
                status = data.splitlines()[0] if data else ""
                m = re.search(r"Server:\s*(.+)", data, flags=re.I)
                server = m.group(1).strip() if m else ""
                return True, f"{status} | Server: {server}"

        elif port == 22:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                banner = s.recv(256).decode(errors="ignore").strip()
                return True, banner

        else:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                try:
                    data = s.recv(512).decode(errors="ignore").strip()
                except:
                    data = ""
                return True, data

    except:
        return False, ""

# -----------------------
# Clasificación
# -----------------------
def classify_device(rdns, netbios, banners, vendor):
    banners_text = " ".join(banners.values()).lower()
    rdns_l = (rdns or "").lower()
    nb_l = (netbios or "").lower()
    vendor_l = (vendor or "").lower()

    if "printer" in rdns_l or "print" in rdns_l or "impresora" in rdns_l:
        return "Impresora/Escáner"
    if "printer" in nb_l or "print" in nb_l:
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

# -----------------------
# SCAN IP (MODIFICADO)
# -----------------------
def scan_ip(ip: str, ports: List[int], timeout: float, retries: int, skip_ping=False, try_arp=True):

    print(f"[..] Escaneando {ip}", flush=True)

    result = {
        "ip": ip,
        "reachable": False,
        "rdns": "",
        "netbios": "",
        "mac": "",
        "vendor": "",
        "device_type": "",
        "banners": {}
    }

    # PING
    print(f"[..] {ip}: ping...", flush=True)
    if not skip_ping:
        result["reachable"] = ping_ip(ip, timeout)
    else:
        result["reachable"] = True
    print(f"[..] {ip}: ping={result['reachable']}", flush=True)

    # DNS
    print(f"[..] {ip}: reverse DNS...", flush=True)
    result["rdns"] = reverse_dns(ip) or ""
    print(f"[..] {ip}: rdns={result['rdns']}", flush=True)

    # NETBIOS
    print(f"[..] {ip}: netbios...", flush=True)
    try:
        result["netbios"] = get_netbios_name(ip) or ""
    except:
        result["netbios"] = ""
    print(f"[..] {ip}: netbios={result['netbios']}", flush=True)

    # ARP
    if try_arp:
        print(f"[..] {ip}: buscando MAC...", flush=True)
        mac = get_mac_from_arp(ip)
        result["mac"] = mac or ""
        result["vendor"] = guess_vendor(mac) or ""
        print(f"[..] {ip}: MAC={result['mac']} vendor={result['vendor']}", flush=True)

    # PUERTOS
    for p in ports:
        print(f"[..] {ip}: probando puerto {p}...", flush=True)
        ok = False
        banner = ""
        for _ in range(retries):
            ok, banner = probe_banner(ip, p, timeout)
            if ok:
                print(f"[..] {ip}: puerto {p} ABIERTO", flush=True)
                result["banners"][p] = banner
                break
        if not ok:
            print(f"[..] {ip}: puerto {p} cerrado/no responde", flush=True)

    # CLASIFICACIÓN
    result["device_type"] = classify_device(
        result["rdns"], result["netbios"], result["banners"], result["vendor"]
    )
    print(f"[OK] {ip}: tipo={result['device_type']}", flush=True)

    return result

# -----------------------
# IO
# -----------------------
def load_ips_from_file(path):
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def generate_ips_from_cidr(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in net.hosts()]

def save_csv(results, out_prefix):
    path = f"{out_prefix}.csv"
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "reachable", "reverse_dns", "netbios", "mac", "vendor", "device_type", "banners"])
        for r in results:
            b = ";".join([f"{p}={banner[:200]}" for p, banner in r["banners"].items()])
            writer.writerow([r["ip"], r["reachable"], r["rdns"], r["netbios"], r["mac"], r["vendor"], r["device_type"], b])
    print(f"[+] Guardado CSV: {path}", flush=True)
    return path

def save_json(results, out_prefix):
    path = f"{out_prefix}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[+] Guardado JSON: {path}", flush=True)
    return path

def save_summary(results, out_prefix):
    path = f"resumen_{out_prefix}.txt"
    types_count = defaultdict(int)
    for r in results:
        types_count[r["device_type"]] += 1

    with open(path, "w", encoding="utf-8") as f:
        f.write("Resumen del escaneo:\n\n")
        f.write(f"Total IPs escaneadas: {len(results)}\n\n")
        for t, c in sorted(types_count.items(), key=lambda x: -x[1]):
            f.write(f"{t}: {c}\n")

    print(f"[+] Guardado resumen: {path}", flush=True)
    return path

# -----------------------
# MAIN
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Escaneo de IPs con heurísticas y progreso para GUI.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cidr")
    group.add_argument("--file")
    parser.add_argument("--out-prefix", default=DEFAULT_OUT_PREFIX)
    parser.add_argument("--ports", default=",".join(str(x) for x in DEFAULT_PORTS))
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--no-arp", action="store_true")
    parser.add_argument("--skip-ping", action="store_true")
    args = parser.parse_args()

    if args.cidr:
        print(f"[+] Generando IPs desde CIDR {args.cidr}", flush=True)
        ips = generate_ips_from_cidr(args.cidr)
    else:
        print(f"[+] Leyendo IPs desde archivo {args.file}", flush=True)
        ips = load_ips_from_file(args.file)

    ports = [int(p) for p in args.ports.split(",")]

    print(f"[+] Total IPs: {len(ips)} | Puertos: {ports} | Workers: {args.workers}", flush=True)

    results = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)
    futures = {executor.submit(scan_ip, ip, ports, args.timeout, args.retries, args.skip_ping, not args.no_arp): ip for ip in ips}

    for fut in concurrent.futures.as_completed(futures):
        ip = futures[fut]
        try:
            res = fut.result()
            results.append(res)
        except Exception as e:
            print(f"[ERROR] Falló {ip}: {e}", flush=True)

    print("[+] Guardando archivos...", flush=True)
    save_csv(results, args.out_prefix)
    save_json(results, args.out_prefix)
    save_summary(results, args.out_prefix)

    print("[✔] ESCANEO COMPLETO", flush=True)

if __name__ == "__main__":
    main()
