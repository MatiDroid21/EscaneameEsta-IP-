# 🔎 escaneame_esta.py — v3.0.1
> Corrección de Errores minimos que afectaban en el escaneo
> 💻 Escaneo local de red con interfaz gráfica, heurística de identificación y evaluación de riesgo

> 📡 **Escaneo de IPs con heurística de identificación**  
> 🧑‍💻 Autor: **MatiDroid21**

Una herramienta ligera y poderosa para **mapear, clasificar y priorizar dispositivos en red local** usando señales como ping, DNS inverso, NetBIOS, MAC/OUI desde ARP, banner grabbing, detección de indicios de minería y scoring de riesgo.

Ideal para:
- 🖨️ Inventario rápido de red
- 🛠️ Análisis superficial
- 🧠 Clasificación automática de dispositivos
- 🚨 Priorización de hosts con riesgo

⚠️ **Úsalo solo con autorización. Escanear redes sin permiso puede ser ilegal.**

---

## ⚡️ Contenido rápido

| 🏷️ | Descripción |
|-----|-------------|
| 📦 Versión | `v3.1` — CLI robusto, GUI Tkinter, evaluación de riesgo y detección heurística opcional |
| 🎯 Entrada | `--cidr` o `--file` |
| 📁 Salida | CSV, JSON y TXT resumen |
| 🖥️ Interfaz | GUI Tkinter con log en tiempo real |
| ⚙️ Dependencias | `tqdm`, `nbtscan`, `arping`, `nbtstat` (opcionales) |
| 🧪 Extras | `--crypto-scan` para indicios de minería |
| 📊 Riesgo | `risk_score`, `risk_level`, `findings`, `recommendations` |

---

## 🌟 Características principales

✅ **CLI flexible**:  
`--ports`, `--retries`, `--timeout`, `--workers`, `--no-arp`, `--skip-ping`, `--crypto-scan`

✅ **GUI incluida**:
- Interfaz Tkinter sencilla y clara.
- Log en tiempo real sin bloquear la ventana.
- Ejecuta el escaneo en segundo plano.

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

✅ **Evaluación de riesgo**:
- Puntaje por puertos sensibles y señales expuestas.
- Nivel de riesgo: `low`, `medium`, `high`, `critical`.
- Recomendaciones automáticas para revisar hosts prioritarios.

✅ **Detección heurística de minería cripto**:
- Marca indicios por puertos y servicios asociados.
- Útil como señal temprana, no como confirmación definitiva.

---

## 🧰 Requisitos

| Tipo | Requisito |
|------|----------|
| 🐍 Python | 3.8 o superior |
| 📦 Módulos | `argparse`, `ipaddress`, `socket`, `ssl`, `csv`, `json`, `subprocess`, `threading`, `tkinter`, etc. (todos estándar) |
| 📦 Opcional | `tqdm`, `nbtscan`, `arping`, `nmap` |

Algunas funciones pueden requerir permisos de **administrador/root**.

---

## 🚀 Instalación rápida

```bash
# 1. Clona o descarga este repositorio
git clone https://github.com/MatiDroid21/escaneame_esta.git
cd escaneame_esta

# 2. (Opcional) Crea un entorno virtual
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
.venv\Scripts\activate      # Windows

# 3. Instala tqdm si deseas barra de progreso
pip install tqdm
```

---

## 🛠️ Uso básico

### 🔍 Escaneo de un rango CIDR

```bash
python escaneame_esta.py --cidr 192.168.1.0/24
```

### 📄 Escaneo desde archivo de IPs

```bash
python escaneame_esta.py --file ips.txt --out-prefix mi_red
```

### 🧪 Ejemplo completo

```bash
python escaneame_esta.py \
  --cidr 10.0.0.0/24 \
  --ports 22,80,443,139,445 \
  --workers 100 \
  --timeout 1.0 \
  --retries 2 \
  --crypto-scan
```

### 🖥️ Uso de la GUI

```bash
python gui_escaneame.py
```

La GUI ejecuta el escaneo en segundo plano y muestra el log en tiempo real sin bloquear la ventana.

---

## ⚙️ Opciones CLI

| Opción | Descripción |
|--------|-------------|
| `--cidr` | Rango CIDR a escanear |
| `--file` | Archivo con IPs (uno por línea) |
| `--out-prefix` | Prefijo para salida (default: `hosts_escaneados`) |
| `--ports` | Puertos a escanear (ej. `22,80,443`) |
| `--workers` | Hilos simultáneos (default: `50`) |
| `--timeout` | Timeout por intento (segundos) |
| `--retries` | Reintentos por puerto |
| `--no-arp` | Desactiva detección por ARP |
| `--skip-ping` | Salta el ping inicial |
| `--crypto-scan` | Activa la detección heurística de indicios de minería |

---

## 📤 Archivos de salida

| Archivo | Descripción |
|--------|-------------|
| `<prefix>.csv` | Resultados por host en formato tabular |
| `<prefix>.json` | Estructura completa legible |
| `resumen_<prefix>.txt` | Resumen con estadísticas |

---

## 🧾 Ejemplo de salida CSV

```csv
ip,reachable,reverse_dns,netbios,mac,vendor,device_type,risk_score,risk_level,crypto_suspicion,banners
192.168.1.10,True,printer.local,HP-LASER,00:1A:2B:3C:4D:5E,HP,Impresora/Escáner,45,high,False,80=HTTP/1.1 200 OK | Server: HP-Device
```

---

## 🧠 Clasificación heurística

🧩 Se basa en múltiples señales:

- 🔤 Nombres de host (reverse DNS, NetBIOS)
- 🏷️ Banners de servicios (HTTP, SSH, SMB)
- 🔍 Certificados TLS
- 🔌 OUI del MAC (fabricante)

🎯 Clasifica dispositivos como:

- Impresoras.
- Servidores.
- Equipos Windows.
- Cámaras IP.
- Dispositivos Apple.
- Routers.
- IoT.
- Hosts genéricos o no identificados.

⚠️ Puede haber falsos positivos/negativos.

---

## 🚨 Evaluación de riesgo

La herramienta suma puntos cuando detecta servicios sensibles o expuestos. El resultado ayuda a priorizar qué hosts revisar primero.

### Nivel de riesgo

- `low`
- `medium`
- `high`
- `critical`

### Señales que elevan el riesgo

- Puertos de administración expuestos.
- SMB, RDP, Telnet, FTP o bases de datos abiertas.
- Servicios sin cifrado o mal expuestos.
- Indicios de minería cripto.

### Recomendaciones automáticas

El escáner puede sugerir acciones como:

- Revisar firewall o segmentación.
- Cerrar servicios innecesarios.
- Restringir acceso administrativo.
- Validar si un servicio expuesto es realmente necesario.

---

## 🧪 Detección de minería cripto

Esta función agrega una revisión adicional de puertos que suelen aparecer en entornos asociados a minería o pools de minería.

- Úsala como señal temprana.
- No reemplaza una validación manual.
- Puede marcar servicios legítimos que compartan puertos similares.

---

## ✅ Recomendaciones de uso

- 🔍 Empieza con pruebas pequeñas: `/30` o algunas IPs.
- ⚙️ Ajusta `--timeout` y `--workers` según el rendimiento de tu red.
- 💡 Usa `--crypto-scan` solo si quieres revisar indicios de minería.
- 🚨 Revisa primero los hosts con `risk_level` alto o crítico.
- 🔐 Escanea solo redes que te pertenecen o donde tengas permiso.

---

## 📝 Notas

- Si el escaneo termina de inmediato en la GUI, revisa que `escaneame_esta.py` esté en la misma carpeta.
- Si no ves `tqdm`, no es obligatorio para que el programa funcione.
- La salida CSV/JSON queda en el directorio desde donde ejecutas el programa.
'''
(out / 'README.md').write_text(readme, encoding='utf-8')
print((out / 'README.md').as_posix())

