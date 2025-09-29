
#!/usr/bin/env python3

"""
escaneame_esta.py — Escaneo de IPs con heurística de identificación

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
from typing import Optional, Dict, List, Tuple

# Constantes
PING_TIMEOUT = 1  # segundos
SOCKET_TIMEOUT = 1.0
DEFAULT_OUT_PREFIX = "hosts_escaneados"
COMMON_TCP_PORTS = [22, 80, 443, 139, 445]  # SNMP 161 no se prueba TCP

# Mapeo OUI ejemplo
OUI_MAP = {
    "00:11:22": "DELL",
    "00:15:5D": "MICROSOFT",
    "00:1A:2B": "HP",
    "00:09:5B": "CISCO",
    "44:65:0D": "APPLE",
    "00:0C:29": "VMWARE",
    "F4:5C:89": "HUAWEI",
}

def ping_ip(ip: str) -> bool:
    """Hace ping a una IP para determinar alcance."""
    plat = platform.system().lower()
    if "windows" in plat:
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def reverse_dns(ip: str) -> Optional[str]:
    """Obtiene el nombre inverso de DNS si existe."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None

def get_netbios_name(ip: str) -> Optional[str]:
    """Intenta obtener nombre NetBIOS según plataforma."""
    plat = platform.system().lower()
    if "windows" in plat:
        return netbios_windows(ip)
    else:
        return netbios_nbtscan(ip)

def netbios_windows(ip: str) -> Optional[str]:
    try:
        proc = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3)
        for line in proc.stdout.splitlines():
            if "<00>" in line:
                return line.split()[0].strip()
    except Exception:
        pass
    return None

def netbios_nbtscan(ip: str) -> Optional[str]:
    nbtscan_path = shutil.which("nbtscan")
    if not nbtscan_path:
        return None
    try:
        proc = subprocess.run([nbtscan_path, "-s:", ip], capture_output=True, text=True, timeout=3)
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                name_field = parts[1]
                name = name_field.split("<")[0]
                return name
    except Exception:
        pass
    return None

def get_mac_from_arp(ip: str) -> Optional[str]:
    """Obtiene MAC de la tabla ARP local."""
    plat = platform.system().lower()
    try:
        if "windows" in plat:
            proc = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=2)
            m = re.search(r"([0-9a-fA-F]{2}([-:])[0-9a-fA-F]{2}(\2[0-9a-fA-F]{2}){4})", proc.stdout)
            if m:
                return m.group(1).replace("-", ":").lower()
        else:
            proc = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=2)
            m = re.search(r"([0-9a-fA-F:]{17})", proc.stdout)
            if m:
                return m.group(1).lower()
            # fallback arp
            proc = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=2)
            m = re.search(r"([0-9a-fA-F:]{17})", proc.stdout)
            if m:
                return m.group(1).lower()
    except Exception:
        pass
    return None

def guess_vendor(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    prefix = mac.upper()[0:8]
    return OUI_MAP.get(prefix)

def probe_tcp_banner(ip: str, port: int) -> Tuple[bool, str]:
    """Intenta conectar TCP y obtener banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SOCKET_TIMEOUT)
            s.connect((ip, port))
            # Leer banner según puerto
            if port == 22:
                data = s.recv(256)
                return True, data.decode(errors="ignore").strip()
            elif port in (80, 443):
                request = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
                s.sendall(request)
                data = s.recv(1024)
                return True, data.decode(errors="ignore").splitlines()[0]
            else:
                data = s.recv(256)
                return True, data.decode(errors="ignore").strip()
    except Exception:
        return False, ""

def classify_device(rdns: Optional[str], netbios: Optional[str], banners: Dict[int,str], mac_vendor: Optional[str]) -> str:
    """Clasifica dispositivo según heurísticas."""
    rdns_l = (rdns or "").lower()
    nb_l = (netbios or "").lower()
    vendor_l = (mac_vendor or "").lower() if mac_vendor else ""
    banners_concat = " ".join(banners.values()).lower()

    # Impresora/Escáner heurística
    if any(x in rdns_l for x in ["printer", "print", "impresora", "epson", "hp", "xerox"]) or \
       any(x in nb_l for x in ["printer", "print"]) or \
       any(x in banners_concat for x in ["printer", "hp pjl", "epson", "xerox"]):
        return "Impresora/Escáner"

    # Equipo de red
    if mac_vendor and any(v in vendor_l for v in ["cisco", "huawei"]):
        return "Equipo de red (switch/router)"

    # Servidor web
    if any(port in banners and banners[port] for port in (80, 443)) or "server:" in banners_concat:
        return "Servidor Web / HTTP"

    # Servidor Linux/UNIX (SSH)
    if 22 in banners and "openssh" in banners[22].lower():
        return "Servidor Linux/UNIX (SSH)"

    # Windows / SMB
    if any(port in banners and banners[port] for port in (139, 445)) or \
       ("desktop" in nb_l or ("server" in nb_l and "windows" in nb_l)):
        return "Equipo Windows (posible SMB/NetBIOS)"

    # Apple Mac
    if mac_vendor and "apple" in vendor_l:
        return "Equipo Apple (Mac)"

    # Fallback
    if any(port in banners and banners[port] for port in (22, 80, 443)):
        return "Dispositivo (HTTP/SSH) - posible servidor o IoT"

    return "Equipo (cliente / no identificado)"

def scan_ip(ip: str) -> Dict:
    """Escanea una IP y devuelve dict con datos y clasificaciones."""
    reachable = ping_ip(ip)
    rdns = reverse_dns(ip) or ""
    netbios = get_netbios_name(ip) or ""
    mac = get_mac_from_arp(ip) or ""
    vendor = guess_vendor(mac) or ""

    banners = {}
    for port in COMMON_TCP_PORTS:
        ok, banner = probe_tcp_banner(ip, port)
        if ok:
            banners[port] = banner

    device_type = classify_device(rdns, netbios, banners, vendor)

    return {
        "ip": ip,
        "reachable": reachable,
        "rdns": rdns,
        "netbios": netbios,
        "mac": mac,
        "vendor": vendor,
        "device_type": device_type,
        "banners": banners
    }

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
    with open(path, "w", encoding="utf-8") as f:
        f.write("ip,reachable,reverse_dns,netbios,mac,vendor,device_type,banners\n")
        for r in results:
            b_str = ";".join(f"{p}={r['banners'].get(p, '')}".replace(",", " ")[:200] for p in r['banners'])
            f.write(f"{r['ip']},{r['reachable']},{r['rdns']},{r['netbios']},{r['mac']},{r['vendor']},{r['device_type']},{b_str}\n")
    print(f"[+] Guardado CSV: {path}")
    return path

def save_summary(results: List[Dict], out_prefix: str) -> str:
    path = f"resumen_{out_prefix}.txt"
    types_count = {}
    name_to_ips = {}
    ip_to_names = {}

    for r in results:
        types_count[r["device_type"]] = types_count.get(r["device_type"], 0) + 1
        ip = r["ip"]
        names = set(filter(None, [r["rdns"], r["netbios"]]))
        ip_to_names[ip] = names
        for name in names:
            name_to_ips.setdefault(name, set()).add(ip)

    with open(path, "w", encoding="utf-8") as f:
        f.write("Resumen del escaneo\n")
        f.write(f"Total IPs escaneadas: {len(results)}\n\n")

        f.write("Conteo por tipo de dispositivo:\n")
        for device_type, count in sorted(types_count.items(), key=lambda x: -x[1]):
            f.write(f"  {device_type}: {count}\n")

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

def save_json(results: List[Dict], out_prefix: str) -> str:
    path = f"{out_prefix}.json"
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[+] Guardado JSON: {path}")
    except Exception as e:
        print(f"[ERROR] Falló guardado JSON: {e}")
    return path

def main():
    parser = argparse.ArgumentParser(description="Escaneo de IPs con heurísticas de identificación.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cidr", help="Rango CIDR para escanear, ej: 192.168.1.0/24")
    group.add_argument("--file", help="Archivo con IPs a escanear, una por línea")
    parser.add_argument("--out-prefix", default=DEFAULT_OUT_PREFIX, help="Prefijo para archivos de salida")

    args = parser.parse_args()

    # Obtener lista de IPs
    if args.cidr:
        print(f"[+] Generando IPs desde CIDR: {args.cidr}")
        ips = generate_ips_from_cidr(args.cidr)
    else:
        print(f"[+] Cargando IPs desde archivo: {args.file}")
        ips = load_ips_from_file(args.file)

    print(f"[+] Total IPs a escanear: {len(ips)}")

    start_time = time.time()

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                res = future.result()
                results.append(res)
                print(f"[+] Escaneado {ip}: {res['device_type']}")
            except Exception as e:
                print(f"[ERROR] Fallo al escanear {ip}: {e}")

    elapsed = time.time() - start_time
    print(f"[+] Escaneo finalizado en {elapsed:.1f}s. Guardando archivos...")

    save_csv(results, args.out_prefix)
    save_json(results, args.out_prefix)
    save_summary(results, args.out_prefix)

if __name__ == "__main__":
    main()

