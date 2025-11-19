# 🔎 escaneame_esta.py — v2.2
> 💻 Ahora con interfaz grafica

> 📡 **Escaneo de IPs con heurística de identificación**  
> 🧑‍💻 Autor: **MatiDroid21**

Una herramienta ligera y poderosa para **mapear y clasificar dispositivos en red local** usando heurísticas como: ping, DNS inverso, NetBIOS, MAC/OUI desde ARP, banner grabbing y más.

Ideal para:
- 🖨️ Inventario rápido de red
- 🛠️ Análisis superficial
- 🧠 Clasificación automática de dispositivos

⚠️ **Úsalo solo con autorización. Escanear redes sin permiso es ilegal.**

---

## ⚡️ Contenido rápido

| 🏷️ | Descripción |
|-----|-------------|
| 📦 Versión        | `v2.1` — CLI ampliado, mejor banner grabbing, salidas robustas |
| 🎯 Entrada        | `--cidr` o `--file` |
| 📁 Salida         | CSV, JSON y TXT resumen |
| ⚙️ Dependencias   | `nbtscan`, `arping`, `nmap`, `tqdm` (opcionales) |

---

## 🌟 Características principales

✅ **CLI flexible**:  
`--ports`, `--retries`, `--timeout`, `--workers`, `--no-arp`, `--use-nmap`, `--skip-ping`

✅ **Banner grabbing avanzado**:
- 🌐 HTTP/1.1 (`Server:` headers)
- 🔐 TLS (cert subject)
- 🔑 SSH

✅ **Cachés inteligentes y fallbacks**:
- ARP local 🧠
- Soporte para `nbtscan` y `nbtstat` 🗂️
- `arping` para poblar tabla ARP 📡

✅ **Formatos de salida limpios y útiles**:
- 📄 CSV (con `csv` module)
- 🧾 JSON legible
- 📋 Resumen TXT con insights

✅ **Clasificación automática**:
- Heurística basada en banners, DNS, OUI, NetBIOS y certificados TLS 🔍

---

## 🧰 Requisitos

| Tipo       | Requisito                      |
|------------|-------------------------------|
| 🐍 Python   | 3.8 o superior                |
| 📦 Módulos  | `argparse`, `ipaddress`, `socket`, `ssl`, `csv`, `json`, `subprocess`, etc. (todos estándar) |
| 📦 Opcional | `tqdm`, `nbtscan`, `arping`, `nmap` |

Algunas funciones requieren permisos de **administrador/root**.

---

## 🚀 Instalación rápida

```bash
# 1. Clona o descarga este repositorio
git clone https://github.com/MatiDroid21/escaneame_esta.git
cd escaneame_esta

# 2. (Opcional) Crea un entorno virtual
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
.venv\Scripts\activate         # Windows

# 3. Instala tqdm si deseas barra de progreso
pip install tqdm
🛠️ Uso básico
🔍 Escaneo de un rango CIDR:
python escaneame_esta.py --cidr 192.168.1.0/24
📄 Escaneo desde archivo de IPs:
python escaneame_esta.py --file ips.txt --out-prefix mi_red
🧪 Ejemplo completo:
python escaneame_esta.py \
  --cidr 10.0.0.0/24 \
  --ports 22,80,443,139,445 \
  --workers 100 \
  --timeout 1.0 \
  --retries 2 \
  --use-nmap
⚙️ Opciones CLI
Opción	Descripción
--cidr	Rango CIDR a escanear
--file	Archivo con IPs (uno por línea)
--out-prefix	Prefijo para salida (default: hosts_escaneados)
--ports	Puertos a escanear (ej. 22,80,443)
--workers	Hilos simultáneos (default: 50)
--timeout	Timeout por intento (segundos)
--retries	Reintentos por puerto
--no-arp	Desactiva detección por ARP
--skip-ping	Salta el ping inicial
--use-nmap	Ejecuta nmap -sV -O si está instalado

📤 Archivos de salida
Archivo	Descripción
<prefix>.csv	Resultados por host (tabulado)
<prefix>.json	Estructura completa legible
resumen_<prefix>.txt	Resumen con estadísticas
<prefix>_nmap.xml (opt)	Resultado de nmap (si se usa --use-nmap)

🧾 Ejemplo de salida CSV:
cs
Copiar código
ip,reachable,reverse_dns,netbios,mac,vendor,device_type,banners
192.168.1.10,True,printer.local,HP-LASER,00:1A:2B:3C:4D:5E,HP,Impresora,80=HTTP/1.1 200 OK | Server: HP-Device
🧠 Clasificación heurística
🧩 Se basa en múltiples señales:

🔤 Nombres de host (reverse DNS, NetBIOS)

🏷️ Banners de servicios (HTTP, SSH, SMB)

🔍 Certificados TLS

🔌 OUI del MAC (fabricante)

🎯 Clasifica dispositivos como:

Impresoras, servidores, equipos Windows, cámaras IP, dispositivos Apple, routers, IoT, etc.

⚠️ Puede haber falsos positivos/negativos.

✅ Recomendaciones de uso
🔍 Empieza con pruebas pequeñas: /30 o algunas IPs.

⚙️ Ajusta --timeout y --workers para mejor rendimiento.

💡 Usa --use-nmap para análisis más profundo.

🔐 Escanea solo redes que te pertenecen o donde tengas permiso.


