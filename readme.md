escaneame_esta.py

Escaner rápido de hosts en una red local con identificación heurística basada en ping, DNS inverso, NetBIOS, ARP, banners TCP y OUI MAC.

Descripción

escaneame_esta.py es una pequeña utilidad en Python para mapear hosts en una red y generar un inventario básico: determina si una IP responde, intenta obtener nombres (DNS inverso, NetBIOS), consulta la tabla ARP local para obtener MACs, prueba puertos TCP comunes para capturar banners y aplica reglas heurísticas para clasificar el tipo de dispositivo (impresora, servidor web, equipo Windows, routers/switches, etc.). Produce salida en CSV, JSON y un resumen en texto.

Características

Escaneo por rango CIDR o lista de IPs.

Multihilo para mayor rapidez (ThreadPoolExecutor).

Detección de vendor por OUI (mapa simple embebido).

Recolección de banners en puertos 22, 80, 443, 139, 445.

Exporta:

CSV con campos principales.

JSON con los objetos completos por host.

Resumen TXT con estadística y posibles duplicados.

Requisitos

Python 3.7+ (recomendado 3.8+)

Utilidades (opcional, según plataforma):

Linux/macOS: ip o arp, nbtscan (opcional)

Windows: arp, nbtstat

Acceso a la red y permisos para ejecutar comandos de red (ej. tabla ARP).

Módulos Python (todos estándar): ipaddress, concurrent.futures, socket, subprocess, json, re, shutil, time.

Instalación

Clona o copia el script en tu máquina.

Asegúrate de tener Python 3 instalado.

(Opcional) Instala nbtscan si quieres mejorar la detección NetBIOS en Unix:

En Debian/Ubuntu: sudo apt install nbtscan

Da permisos de ejecución si lo vas a ejecutar directamente:

chmod +x escaneame_esta.py

Uso

Escanear un rango CIDR completo:

python escaneame_esta.py --cidr 192.168.1.0/24


Escanear IPs desde un archivo (una IP por línea, permite comentarios con #):

python escaneame_esta.py --file ips.txt --out-prefix mi_red


Opciones:

--cidr : Rango CIDR a escanear.

--file : Archivo con IPs (mutuamente exclusivo con --cidr).

--out-prefix : Prefijo para archivos de salida (por defecto hosts_escaneados).

Formato de salida
JSON

Archivo <out-prefix>.json con una lista de objetos. Ejemplo (fragmento):

[
  {
    "ip": "192.168.1.10",
    "reachable": true,
    "rdns": "printer-office.example.local",
    "netbios": "PRINTER-1",
    "mac": "44:65:0d:aa:bb:cc",
    "vendor": "APPLE",
    "device_type": "Impresora/Escáner",
    "banners": {
      "80": "HTTP/1.1 200 OK",
      "443": "HTTP/1.1 200 OK"
    }
  }
]

CSV

Archivo <out-prefix>.csv con columnas:
ip,reachable,reverse_dns,netbios,mac,vendor,device_type,banners.

Resumen TXT

resumen_<out-prefix>.txt incluye:

Totales escaneados.

Conteo por tipo de dispositivo.

Nombres (rdns/netbios) apuntando a múltiples IPs.

IPs con múltiples nombres.

Notas sobre heurísticas y falsas detecciones posibles.

Ejemplos

Escaneo rápido de una /29:

python escaneame_esta.py --cidr 10.0.0.0/29 --out-prefix oficina


Escaneo desde lista:
ips.txt:

# Red de cámaras
10.0.1.10
10.0.1.11
# Impresora
10.0.1.20

python escaneame_esta.py --file ips.txt --out-prefix camaras_impresora

Buenas prácticas y seguridad

Solo escanea redes que administras o para las cuales tienes permiso explícito. El escaneo no autorizado puede considerarse intrusivo o ilegal.

Ejecuta el script desde una máquina con conectividad a la red objetivo (preferible desde la LAN).

Para obtener MACs desde ARP, algunos sistemas requieren que la IP haya sido contactada recientemente; usa ARP/neighbor discovery con cuidado.

Ten en cuenta que banners y nombres son susceptibles a falsificación; úsalo como ayuda para inventariado, no como prueba absoluta.

Limitaciones y mejoras sugeridas

OUI embebido es limitado; integrar consultas a una base OUI completa mejoraría la detección.

Soporte para ICMP en plataformas con restricciones (necesita privilegios en algunos SO).

Añadir opciones para ajustar timeout, puertos y concurrencia.

Exportar a formatos adicionales (Excel, SQLite).

Incorporar escaneo UDP/SMB/SNMP para mejorar identificación (con cuidado y permisos).

Licencia

El código es provisto por MatiDroid21. Añade la licencia que prefieras (por ejemplo MIT) o indícalo en un archivo LICENSE.

Contacto / Créditos

Autor: MatiDroid21
Código original y heurísticas de identificación: implementadas en el script.

Nota final

Usa el script para inventario y diagnóstico en redes propias o con permiso. La detección es heurística y pensada para facilitar tareas de administración, no para auditoría forense.