#!/usr/bin/env python3
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
from collections import Counter
from dataclasses import asdict, dataclass, field
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
DEFAULT_RISK_PORTS = {
    21: 20, 23: 30, 80: 10, 110: 15, 139: 25, 143: 15, 389: 10, 443: 10,
    445: 35, 465: 15, 514: 20, 587: 15, 631: 20, 1433: 30, 1521: 30,
    2049: 25, 2375: 35, 3306: 30, 3389: 40, 5432: 30, 5900: 35, 5985: 25,
    6379: 30, 8080: 10, 9200: 30,
}

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
    risk_score: int = 0
    risk_level: str = "low"
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
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
    return OUI_MAP.get(mac.upper()[0:8], "")

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
    return {"has_crypto": bool(open_ports), "open_ports": open_ports, "details": details}

def risk_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"

def score_risk(ip: str, reachable: bool, rdns: str, netbios: str, banners: Dict[int, str], crypto: bool) -> Tuple[int, List[str], List[str]]:
    score = 0
    findings = []
    recs = []
    for port in banners:
        if port in DEFAULT_RISK_PORTS:
            score += DEFAULT_RISK_PORTS[port]
            findings.append(f"Puerto sensible abierto: {port}")
    if 445 in banners or 139 in banners:
        recs.append("Revisar exposición de SMB y limitar acceso por firewall o VLAN.")
    if 23 in banners:
        recs.append("Cerrar Telnet y usar SSH.")
    if 21 in banners:
        recs.append("Validar si FTP es necesario y migrar a SFTP/FTPS.")
    if 3389 in banners:
        recs.append("Restringir RDP a redes de administración.")
    if 3306 in banners or 5432 in banners or 1433 in banners:
        recs.append("Restringir acceso a bases de datos solo a hosts autorizados.")
    if 2375 in banners:
        recs.append("Docker sin TLS expuesto: revisar de inmediato.")
    if 9200 in banners:
        recs.append("Asegurar motores de búsqueda o índices expuestos.")
    if crypto:
        score += 20
        findings.append("Indicios de minería cripto detectados")
        recs.append("Revisar proceso, conexiones salientes y posibles indicadores de compromiso.")
    if reachable and not banners:
        score += 5
    return min(score, 100), findings, recs

def scan_ip(ip: str, ports: List[int], timeout: float, retries: int, skip_ping: bool = False, try_arp: bool = True, crypto_scan: bool = False, crypto_ports: Optional[List[int]] = None) -> Dict:
    result = ScanResult(ip=ip)
    result.reachable = True if skip_ping else ping_ip(ip, timeout)
    result.rdns = reverse_dns(ip)
    result.netbios = get_netbios_name(ip)
    if try_arp:
        result.mac = get_mac_from_arp(ip)
        result.vendor = guess_vendor(result.mac)
    if result.reachable:
        for p in ports:
            ok = False
            banner = ""
            for _ in range(max(1, retries)):
                ok, banner = probe_banner(ip, p, timeout)
                if ok:
                    break
            if ok:
                result.banners[p] = banner
    if crypto_scan and result.reachable:
        crypto = check_crypto_ports(ip, crypto_ports or DEFAULT_CRYPTO_PORTS, timeout)
        result.crypto_suspicion = crypto["has_crypto"]
        result.crypto_ports = crypto["open_ports"]
        result.crypto_details = crypto["details"]
    result.device_type = classify_device(result.rdns, result.netbios, result.banners, result.vendor)
    result.risk_score, result.findings, result.recommendations = score_risk(
        ip, result.reachable, result.rdns, result.netbios, result.banners, result.crypto_suspicion
    )
    result.risk_level = risk_level(result.risk_score)
    return result.to_dict()

def load_ips_from_file(path: str) -> List[str]:
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def generate_ips_from_cidr(cidr: str) -> List[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in net.hosts()]

def parse_ports(value: str) -> List[int]:
    return [int(part.strip()) for part in value.split(",") if part.strip()]

def save_csv(results: List[Dict], out_prefix: str) -> str:
    path = f"{out_prefix}.csv"
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "reachable", "reverse_dns", "netbios", "mac", "vendor", "device_type", "risk_score", "risk_level", "crypto_suspicion", "findings", "recommendations", "banners"])
        for r in results:
            banners = ";".join([f"{p}={str(banner)[:200]}" for p, banner in r.get("banners", {}).items()])
            writer.writerow([
                r.get("ip", ""), r.get("reachable", False), r.get("rdns", ""), r.get("netbios", ""),
                r.get("mac", ""), r.get("vendor", ""), r.get("device_type", ""), r.get("risk_score", 0),
                r.get("risk_level", "low"), r.get("crypto_suspicion", False), ";".join(r.get("findings", [])),
                ";".join(r.get("recommendations", [])), banners,
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
    risk_count = Counter(r.get("risk_level", "low") for r in results)
    crypto_count = sum(1 for r in results if r.get("crypto_suspicion"))
    with open(path, "w", encoding="utf-8") as f:
        f.write("Resumen del escaneo\\n\\n")
        f.write(f"Total IPs escaneadas: {len(results)}\\n")
        f.write(f"Hosts con indicios de minería: {crypto_count}\\n")
        f.write(f"Critical: {risk_count.get('critical', 0)}\\n")
        f.write(f"High: {risk_count.get('high', 0)}\\n")
        f.write(f"Medium: {risk_count.get('medium', 0)}\\n")
        f.write(f"Low: {risk_count.get('low', 0)}\\n\\n")
        for t, c in types_count.most_common():
            f.write(f"{t}: {c}\\n")
    return path

def main() -> int:
    parser = argparse.ArgumentParser(description="Escaneo de IPs con heurísticas, evaluación de riesgo y progresos")
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

    ips = generate_ips_from_cidr(args.cidr) if args.cidr else load_ips_from_file(args.file)
    ports = parse_ports(args.ports)
    crypto_ports = parse_ports(args.crypto_ports)

    print(f"[+] Total IPs: {len(ips)} | Puertos: {ports} | Workers: {args.workers}", flush=True)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {}
        for ip in ips:
            print(f"[>] Escaneando {ip}", flush=True)
            futures[executor.submit(
                scan_ip,
                ip,
                ports,
                args.timeout,
                args.retries,
                args.skip_ping,
                not args.no_arp,
                args.crypto_scan,
                crypto_ports,
            )] = ip

        iterator = concurrent.futures.as_completed(futures)
        if tqdm:
            iterator = tqdm(iterator, total=len(futures), desc="Escaneando")

        done = 0
        for fut in iterator:
            ip = futures[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                print(f"[ERROR] Falló {ip}: {e}", flush=True)
            done += 1
            print(f"[+] Completado {done}/{len(ips)}: {ip}", flush=True)

    print("Guardando archivos...", flush=True)
    csv_path = save_csv(results, args.out_prefix)
    json_path = save_json(results, args.out_prefix)
    summary_path = save_summary(results, args.out_prefix)
    print(f"[+] Guardado CSV: {csv_path}", flush=True)
    print(f"[+] Guardado JSON: {json_path}", flush=True)
    print(f"[+] Guardado resumen: {summary_path}", flush=True)
    print("ESCANEO COMPLETO", flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
