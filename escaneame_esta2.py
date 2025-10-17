
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

Licencia:
  Coloca aquí la licencia que prefieras (por ejemplo MIT). Si no indicas, se
  entiende uso personal/educativo y responsabilidad del autor/operador.
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

# Opcional: tqdm para barra de progreso
try:
    from tqdm import tqdm
except Exception:
    tqdm = None

# Constantes por defecto
DEFAULT_OUT_PREFIX = "hosts_escaneados"
DEFAULT_PORTS = [22, 80, 443, 139, 445]
DEFAULT_WORKERS = 50
DEFAULT_TIMEOUT = 1.0
DEFAULT_RETRIES = 1

# Mapeo OUI (ejemplo corto; puedes ampliarlo)
OUI_MAP = {
    "00:11:22": "DELL",
    "00:15:5D": "MICROSOFT",
    "00:1A:2B": "HP",
    "00:09:5B": "CISCO",
    "44:65:0D": "APPLE",
    "00:0C:29": "VMWARE",
    "F4:5C:89": "HUAWEI",
}

def run_cmd(cmd: List[str], timeout: float = 3.0) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)

def ping_ip(ip: str, timeout: float = 1.0) -> bool:
    """Ping simple usando utilidad del sistema. No bloqueante grande."""
    plat = platform.system().lower()
    if "windows" in plat:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        # -W timeout en segundos para linux (algunos BSD usan otra sintaxis)
        cmd = ["ping", "-c", "1", "-W", str(int(max(1, timeout)) ), ip]
    rc, out, err = run_cmd(cmd, timeout=timeout + 1)
    return rc == 0

def reverse_dns(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None

# --- NetBIOS helpers ---
def netbios_nbtscan(ip: str) -> Optional[str]:
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
            # segundo campo suele ser NAME<00>
            name_field = parts[1]
            name = name_field.split("<")[0]
            return name
    return None

def netbios_windows(ip: str) -> Optional[str]:
    try:
        proc = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3)
        for line in proc.stdout.splitlines():
            if "<00>" in line:
                return line.split()[0].strip()
    except Exception:
        pass
    return None

def get_netbios_name(ip: str) -> Optional[str]:
    plat = platform.system().lower()
    if "windows" in plat:
        nb = netbios_windows(ip)
        if nb:
            return nb
    # Fallback cross-platform
    return netbios_nbtscan(ip)

# --- ARP helpers ---
arp_cache: Dict[str, Optional[str]] = {}

def get_mac_from_arp(ip: str) -> Optional[str]:
    """Trata de obtener MAC desde caché / ip neigh / arp -n / arping."""
    if ip in arp_cache:
        return arp_cache[ip]

    plat = platform.system().lower()
    mac = None
    # Prefer ip neigh (linux)
    if "linux" in plat:
        try:
            rc, out, err = run_cmd(["ip", "neigh", "show", ip], timeout=1)
            m = re.search(r"([0-9a-fA-F:]{17})", out)
            if m:
                mac = m.group(1).lower()
        except Exception:
            mac = None
    # Fallback arp
    if not mac:
        try:
            rc, out, err = run_cmd(["arp", "-n", ip], timeout=1)
            m = re.search(r"([0-9a-fA-F:]{17})", out)
            if m:
                mac = m.group(1).lower()
        except Exception:
            mac = None

    # Try arping to populate ARP table if not found and arping exists
    if not mac and shutil.which("arping"):
        try:
            rc, out, err = run_cmd(["arping", "-c", "1", "-w", "1", ip], timeout=2)
            # Re-check arp after arping
            rc2, out2, err2 = run_cmd(["arp", "-n", ip], timeout=1)
            m = re.search(r"([0-9a-fA-F:]{17})", out2)
            if m:
                mac = m.group(1).lower()
        except Exception:
            mac = None

    arp_cache[ip] = mac
    return mac

def guess_vendor(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    prefix = mac.upper()[0:8]
    return OUI_MAP.get(prefix)

# --- TCP / TLS probing ---
def probe_tcp_connect(ip: str, port: int, timeout: float) -> Tuple[bool, Optional[socket.socket], Optional[str]]:
    """Abre conexión TCP (no lee), devuelve socket (si se quiere usar)."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        return True, s, ""
    except Exception as e:
        return False, None, str(e)

def probe_banner(ip: str, port: int, timeout: float) -> Tuple[bool, str]:
    """Intenta obtener banner para varios puertos. Retorna (ok, banner_str)."""
    # Reintentos manejados por quien llame
    try:
        if port == 443:
            # TLS: intentar handshake y obtener certificado subject + Server header (sobre TLS)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                with context.wrap_socket(sock, server_hostname=ip) as ss:
                    # Obtener certificado
                    try:
                        cert = ss.getpeercert()
                        subject = cert.get('subject', ())
                        subj_str = " ".join("=".join(x) for part in subject for x in part) if subject else ""
                    except Exception:
                        subj_str = ""
                    # Intentar leer primeros bytes (Server header)
                    try:
                        # Hacer petición HTTP/1.1 para obtener Server header
                        req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                        ss.sendall(req)
                        data = ss.recv(1024)
                        first_line = data.decode(errors="ignore").splitlines()[0] if data else ""
                    except Exception:
                        first_line = ""
                    banner = "cert=" + subj_str + ";resp=" + first_line
                    return True, banner
        elif port in (80,):
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                s.sendall(req)
                data = s.recv(2048)
                # extraer Server: header y status line
                text = data.decode(errors="ignore")
                lines = text.splitlines()
                status = lines[0] if lines else ""
                m = re.search(r"Server:\s*(.+)", text, flags=re.IGNORECASE)
                server_hdr = m.group(1).strip() if m else ""
                return True, f"{status} | Server: {server_hdr}"
        elif port == 22:
            # SSH banner (read banner line)
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                data = s.recv(256)
                b = data.decode(errors="ignore").strip()
                return True, b
        else:
            # Puertos SMB/others: intentar conectar y leer primeros bytes
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                try:
                    data = s.recv(512)
                    b = data.decode(errors="ignore").strip()
                except Exception:
                    b = ""
                return True, b
    except Exception:
        return False, ""

def classify_device(rdns: Optional[str], netbios: Optional[str], banners: Dict[int,str], mac_vendor: Optional[str]) -> str:
    """Clasificación ampliada con heurísticas adicionales."""
    rdns_l = (rdns or "").lower()
    nb_l = (netbios or "").lower()
    vendor_l = (mac_vendor or "").lower() if mac_vendor else ""
    banners_concat = " ".join(banners.values()).lower()

    # Impresora heurística
    if any(x in rdns_l for x in ["printer", "print", "impresora"]) or \
       any(x in nb_l for x in ["printer", "print"]) or \
       any(x in banners_concat for x in ["hp pjl", "epson", "xerox", "printer"]):
        return "Impresora/Escáner"

    # Equipamiento de red por OUI
    if mac_vendor and any(v in vendor_l for v in ["cisco", "huawei", "hpe", "juniper"]):
        return "Equipo de red (switch/router)"

    # Servidor HTTP
    if any((p in banners and banners[p]) for p in (80, 443)) or "server:" in banners_concat:
        return "Servidor Web / HTTP"

    # SSH -> probablemente unix/linux server
    if 22 in banners and "openssh" in banners[22].lower():
        return "Servidor Linux/UNIX (SSH)"

    # SMB/Windows heurística
    if any(p in banners and banners[p] for p in (139, 445)) or "microsoft-ds" in banners_concat or "samba" in banners_concat:
        return "Equipo Windows (SMB/NetBIOS)"

    # Apple
    if mac_vendor and "apple" in vendor_l:
        return "Equipo Apple (Mac/iOS)"

    # TLS certificate indicates device type (e.g., printer certs sometimes have model)
    if 443 in banners and "cert=" in (banners[443] or "").lower():
        certinfo = (banners[443] or "").lower()
        if any(k in certinfo for k in ["printer", "hp", "xerox", "epson"]):
            return "Impresora/Escáner (detectada por cert)"
        if "iot" in certinfo or "camera" in certinfo:
            return "IoT / Cámara"

    # Fallback
    if any(p in banners and banners[p] for p in (22, 80, 443)):
        return "Dispositivo (HTTP/SSH) - posible servidor o IoT"

    return "Equipo (cliente / no identificado)"

def scan_ip(ip: str, ports: List[int], timeout: float, retries: int, skip_ping: bool=False, try_arp: bool=True) -> Dict:
    """Escanea una IP y devuelve un dict con los resultados."""
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

    # Ping (opcional)
    if not skip_ping:
        try:
            result["reachable"] = ping_ip(ip, timeout=timeout)
        except Exception:
            result["reachable"] = False
    else:
        result["reachable"] = True  # si el usuario decide saltar ping, asumimos intentar puertos

    # DNS reverso
    result["rdns"] = reverse_dns(ip) or ""

    # NetBIOS
    try:
        nb = get_netbios_name(ip)
        result["netbios"] = nb or ""
    except Exception:
        result["netbios"] = ""

    # MAC / OUI
    if try_arp:
        mac = get_mac_from_arp(ip)
        result["mac"] = mac or ""
        result["vendor"] = guess_vendor(mac) or ""
    else:
        result["mac"] = ""
        result["vendor"] = ""

    # Probar puertos con reintentos simples
    for p in ports:
        ok = False
        banner = ""
        for attempt in range(retries):
            ok, banner = probe_banner(ip, p, timeout=timeout)
            if ok:
                result["banners"][p] = banner
                break
            # else: retry (no sleep heavy to avoid long total runtime)
        # si no ok, no lo añadimos (mantener solo abiertos)

    # Clasificar
    result["device_type"] = classify_device(result["rdns"], result["netbios"], result["banners"], result["vendor"])
    return result

# --- IO helpers ---
def load_ips_from_file(path: str) -> List[str]:
    ips = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ips.append(line)
    return ips

def generate_ips_from_cidr(cidr: str) -> List[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in net.hosts()]

def save_csv(results: List[Dict], out_prefix: str) -> str:
    path = f"{out_prefix}.csv"
    with open(path, "w", encoding="utf-8", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "reachable", "reverse_dns", "netbios", "mac", "vendor", "device_type", "banners"])
        for r in results:
            # Consolidar banners en un string seguro
            b_items = []
            for p, b in r["banners"].items():
                cleaned = (b or "").replace("\n", " ").replace("\r", " ")
                b_items.append(f"{p}={cleaned[:300]}")
            b_str = ";".join(b_items)
            writer.writerow([r["ip"], r["reachable"], r["rdns"], r["netbios"], r["mac"], r["vendor"], r["device_type"], b_str])
    print(f"[+] Guardado CSV: {path}")
    return path

def save_json(results: List[Dict], out_prefix: str) -> str:
    path = f"{out_prefix}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[+] Guardado JSON: {path}")
    return path

def save_summary(results: List[Dict], out_prefix: str) -> str:
    path = f"resumen_{out_prefix}.txt"
    types_count = defaultdict(int)
    name_to_ips = defaultdict(set)
    ip_to_names = {}

    for r in results:
        types_count[r["device_type"]] += 1
        ip = r["ip"]
        names = set(filter(None, [r["rdns"], r["netbios"]]))
        ip_to_names[ip] = names
        for name in names:
            name_to_ips[name].add(ip)

    with open(path, "w", encoding="utf-8") as f:
        f.write("Resumen del escaneo\n")
        f.write(f"Total IPs escaneadas: {len(results)}\n\n")
        f.write("Conteo por tipo de dispositivo:\n")
        for t, c in sorted(types_count.items(), key=lambda x: -x[1]):
            f.write(f"  {t}: {c}\n")
        f.write("\nNombres (rdns/netbios) que apuntan a múltiples IPs:\n")
        found = False
        for name, ips in name_to_ips.items():
            if len(ips) > 1:
                f.write(f"  {name}: {', '.join(sorted(ips))}\n")
                found = True
        if not found:
            f.write("  Ninguno encontrado.\n")
        f.write("\nIPs con múltiples nombres detectados (rdns vs netbios):\n")
        found2 = False
        for ip, names in ip_to_names.items():
            if len(names) > 1:
                f.write(f"  {ip}: {', '.join(sorted(names))}\n")
                found2 = True
        if not found2:
            f.write("  Ninguno encontrado.\n")
        f.write("\nNotas:\n")
        f.write(" - Identificación heurística basada en banners, nombres y vendor MAC.\n")
        f.write(" - Puede haber falsos positivos.\n")
    print(f"[+] Guardado resumen: {path}")
    return path

# --- Opcional: nmap si está instalado (más detección) ---
def run_nmap_on_ips(ips: List[str], out_prefix: str):
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        print("[!] nmap no encontrado en PATH, saltando nmap.")
        return None
    args = [nmap_path, "-sV", "-O", "-oX", f"{out_prefix}_nmap.xml"] + ips
    print("[*] Ejecutando nmap para detección avanzada (si tienes permiso)...")
    rc, out, err = run_cmd(args, timeout=300)
    if rc == 0:
        print(f"[+] nmap output: {out_prefix}_nmap.xml")
    else:
        print("[!] nmap falló o fue interrumpido.")
    return f"{out_prefix}_nmap.xml" if rc == 0 else None

# --- Main CLI ---
def main():
    parser = argparse.ArgumentParser(description="Escaneo de IPs con heurísticas mejoradas.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cidr", help="Rango CIDR para escanear, ej: 192.168.1.0/24")
    group.add_argument("--file", help="Archivo con IPs a escanear, una por línea")
    parser.add_argument("--out-prefix", default=DEFAULT_OUT_PREFIX, help="Prefijo para archivos de salida")
    parser.add_argument("--ports", default=",".join(str(x) for x in DEFAULT_PORTS), help="Lista de puertos separados por coma (ej: 22,80,443)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Hilos concurrentes")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout socket/ping en segundos")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Reintentos por puerto")
    parser.add_argument("--no-arp", action="store_true", help="No intentar ARP/arping")
    parser.add_argument("--skip-ping", action="store_true", help="No hacer ping previo (intentar puertos directamente)")
    parser.add_argument("--use-nmap", action="store_true", help="Si nmap está instalado, ejecútalo al final")
    args = parser.parse_args()

    # Preparar lista de IPs
    if args.cidr:
        print(f"[+] Generando IPs desde CIDR: {args.cidr}")
        ips = generate_ips_from_cidr(args.cidr)
    else:
        print(f"[+] Cargando IPs desde archivo: {args.file}")
        ips = load_ips_from_file(args.file)

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    print(f"[+] Total IPs a escanear: {len(ips)} | Puertos: {ports} | Workers: {args.workers}")

    start_time = time.time()
    results = []

    # Ejecutar con ThreadPoolExecutor
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)
    futures = {}
    it = ips
    if tqdm:
        pbar = tqdm(total=len(ips), desc="Escaneando")
    else:
        pbar = None

    for ip in it:
        fut = executor.submit(scan_ip, ip, ports, args.timeout, args.retries, args.skip_ping, not args.no_arp)
        futures[fut] = ip

    try:
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                res = fut.result()
                results.append(res)
                print(f"[+] {ip} -> {res['device_type']}")
            except Exception as e:
                print(f"[ERROR] Falló escaneo {ip}: {e}")
            if pbar:
                pbar.update(1)
    finally:
        if pbar:
            pbar.close()
        executor.shutdown(wait=True)

    elapsed = time.time() - start_time
    print(f"[+] Escaneo finalizado en {elapsed:.1f}s. Guardando archivos...")

    save_csv(results, args.out_prefix)
    save_json(results, args.out_prefix)
    save_summary(results, args.out_prefix)

    if args.use_nmap:
        run_nmap_on_ips(ips, args.out_prefix)

if __name__ == "__main__":
    main()
