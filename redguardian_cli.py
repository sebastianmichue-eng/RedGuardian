#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RedGuardian CLI - Herramienta de Análisis de Red (Versión Consola)
Versión: 1.0.0
Uso: Se ejecuta directamente en CMD/Terminal
Requisitos: Python 3.6+, Scapy, psutil
"""

import os
import sys
import json
import csv
import time
import socket
import subprocess
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, send, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ============================================================================
# COLORES Y ESTILOS PARA CONSOLA
# ============================================================================

class Colores:
    """Colores para la consola"""
    ROJO = '\033[91m'
    VERDE = '\033[92m'
    AMARILLO = '\033[93m'
    AZUL = '\033[94m'
    MAGENTA = '\033[95m'
    CIAN = '\033[96m'
    BLANCO = '\033[97m'
    GRIS = '\033[90m'
    RESET = '\033[0m'
    NEGRITA = '\033[1m'
    SUBRAYADO = '\033[4m'
    
    @staticmethod
    def limpiar_pantalla():
        """Limpia la pantalla de la consola"""
        os.system('cls' if os.name == 'nt' else 'clear')


# ============================================================================
# MÓDULO 1: ESCANEO DE RED
# ============================================================================

class ScannerRed:
    """Escanea dispositivos en la red"""
    
    def __init__(self):
        self.dispositivos = []
        self.activo = False
    
    def obtener_ip_local(self):
        """Obtiene la IP local"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def obtener_direccion_mac(self, ip):
        """Obtiene MAC usando ARP"""
        try:
            if not SCAPY_AVAILABLE:
                return "N/A"
            
            solicitud_arp = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            solicitud_broadcast = broadcast/solicitud_arp
            respondidas, no_respondidas = srp(solicitud_broadcast, timeout=1, verbose=False)
            
            for enviada, recibida in respondidas:
                return recibida.hwsrc
            return "N/A"
        except:
            return "N/A"
    
    def obtener_nombre_dispositivo(self, ip):
        """Obtiene el nombre del dispositivo"""
        try:
            nombre = socket.gethostbyaddr(ip)[0]
            return nombre
        except:
            return "Desconocido"
    
    def detectar_tipo_dispositivo(self, ip, mac):
        """Detecta el tipo de dispositivo por MAC"""
        fabricantes = {
            "00:50:F2": "Microsoft/Windows",
            "00:0A:95": "Apple",
            "00:11:95": "Apple",
            "00:1A:A0": "Apple",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU",
            "DC:A6:32": "Raspberry Pi",
            "B8:27:EB": "Raspberry Pi",
            "28:CE:F2": "Cisco",
            "00:04:4B": "3Com",
        }
        
        prefijo_mac = mac[:8].upper()
        for prefijo, fabricante in fabricantes.items():
            if mac.upper().startswith(prefijo):
                return fabricante
        
        return "Dispositivo Genérico"
    
    def escanear_red(self, rango_red):
        """Escanea la red completa"""
        if not SCAPY_AVAILABLE:
            print(f"{Colores.ROJO}❌ Error: Scapy no está instalado{Colores.RESET}")
            return []
        
        self.dispositivos = []
        self.activo = True
        
        print(f"\n{Colores.CIAN}🔍 Escaneando red: {rango_red}{Colores.RESET}")
        print(f"{Colores.GRIS}Esperando respuestas (esto puede tomar un tiempo)...{Colores.RESET}\n")
        
        try:
            solicitud_arp = ARP(pdst=rango_red)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            solicitud_broadcast = broadcast/solicitud_arp
            
            respondidas, no_respondidas = srp(solicitud_broadcast, timeout=3, verbose=False)
            
            for enviada, recibida in respondidas:
                if not self.activo:
                    break
                
                ip = recibida.psrc
                mac = recibida.hwsrc
                nombre = self.obtener_nombre_dispositivo(ip)
                tipo = self.detectar_tipo_dispositivo(ip, mac)
                
                dispositivo = {
                    "ip": ip,
                    "mac": mac,
                    "nombre": nombre,
                    "tipo": tipo,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                
                self.dispositivos.append(dispositivo)
                print(f"  ✅ Encontrado: {Colores.VERDE}{ip}{Colores.RESET} | MAC: {mac}")
            
            return self.dispositivos
        
        except Exception as e:
            print(f"{Colores.ROJO}❌ Error en escaneo: {str(e)}{Colores.RESET}")
            return []


# ============================================================================
# MÓDULO 2: ANÁLISIS DE PUERTOS
# ============================================================================

class AnalizadorPuertos:
    """Analiza puertos abiertos"""
    
    PUERTOS_COMUNES = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP Alternativo",
        8443: "HTTPS Alternativo",
        9200: "Elasticsearch",
        27017: "MongoDB",
        6379: "Redis"
    }
    
    def escanear_puertos(self, ip, timeout=2):
        """Escanea puertos abiertos en una IP"""
        puertos_abiertos = []
        
        print(f"\n{Colores.CIAN}🔓 Escaneando puertos de {ip}{Colores.RESET}\n")
        
        for puerto, servicio in self.PUERTOS_COMUNES.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                resultado = sock.connect_ex((ip, puerto))
                if resultado == 0:
                    puertos_abiertos.append({
                        "puerto": puerto,
                        "servicio": servicio,
                        "estado": "Abierto"
                    })
                    print(f"  {Colores.VERDE}✓{Colores.RESET} Puerto {Colores.AMARILLO}{puerto}{Colores.RESET} - {servicio} (ABIERTO)")
                else:
                    print(f"  {Colores.GRIS}✗{Colores.RESET} Puerto {puerto} - {servicio} (cerrado)")
            except:
                pass
            finally:
                sock.close()
        
        return puertos_abiertos


# ============================================================================
# MÓDULO 3: DETECCIÓN DE VULNERABILIDADES
# ============================================================================

class DetectorVulnerabilidades:
    """Detecta vulnerabilidades"""
    
    VULNERABILIDADES_CONOCIDAS = {
        "SMB": {"puerto": 445, "riesgo": "Alto", "descripcion": "Acceso a recursos compartidos sin protección"},
        "Telnet": {"puerto": 23, "riesgo": "Alto", "descripcion": "Protocolo no cifrado, susceptible a interceptación"},
        "FTP": {"puerto": 21, "riesgo": "Alto", "descripcion": "Protocolo no cifrado para transferencia de archivos"},
        "HTTP": {"puerto": 80, "riesgo": "Medio", "descripcion": "Conexión no cifrada"},
        "SSH": {"puerto": 22, "riesgo": "Bajo", "descripcion": "Protocolo seguro de acceso remoto"},
        "DNS": {"puerto": 53, "riesgo": "Medio", "descripcion": "Posible DNS spoofing"},
        "RDP": {"puerto": 3389, "riesgo": "Alto", "descripcion": "Escritorio remoto expuesto"},
    }
    
    def detectar_vulnerabilidades(self, dispositivo, puertos_abiertos):
        """Detecta vulnerabilidades basadas en puertos"""
        vulnerabilidades = []
        
        for info_puerto in puertos_abiertos:
            puerto = info_puerto["puerto"]
            servicio = info_puerto["servicio"]
            
            if servicio in self.VULNERABILIDADES_CONOCIDAS:
                vuln = self.VULNERABILIDADES_CONOCIDAS[servicio]
                vulnerabilidades.append({
                    "dispositivo": dispositivo,
                    "servicio": servicio,
                    "puerto": puerto,
                    "riesgo": vuln["riesgo"],
                    "descripcion": vuln["descripcion"]
                })
        
        return vulnerabilidades
    
    def calcular_score_seguridad(self, vulnerabilidades):
        """Calcula un score de seguridad 0-100"""
        if not vulnerabilidades:
            return 100
        
        puntos_riesgo = {"Alto": 30, "Medio": 15, "Bajo": 5}
        puntos_perdidos = sum(puntos_riesgo.get(v["riesgo"], 0) for v in vulnerabilidades)
        
        return max(0, 100 - puntos_perdidos)


# ============================================================================
# MÓDULO 4: GENERADOR DE REPORTES
# ============================================================================

class GeneradorReportes:
    """Genera reportes en diferentes formatos"""
    
    def __init__(self):
        self.directorio = "reportes_redguardian"
        if not os.path.exists(self.directorio):
            os.makedirs(self.directorio)
    
    def generar_json(self, datos, nombre=None):
        """Genera reporte JSON"""
        if not nombre:
            nombre = f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        ruta = os.path.join(self.directorio, nombre)
        
        with open(ruta, 'w', encoding='utf-8') as f:
            json.dump(datos, f, indent=2, ensure_ascii=False)
        
        return ruta
    
    def generar_csv(self, dispositivos, nombre=None):
        """Genera reporte CSV"""
        if not nombre:
            nombre = f"dispositivos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        ruta = os.path.join(self.directorio, nombre)
        
        if dispositivos:
            with open(ruta, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=dispositivos[0].keys())
                writer.writeheader()
                writer.writerows(dispositivos)
        
        return ruta
    
    def generar_txt(self, contenido, nombre=None):
        """Genera reporte en texto plano"""
        if not nombre:
            nombre = f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        ruta = os.path.join(self.directorio, nombre)
        
        with open(ruta, 'w', encoding='utf-8') as f:
            f.write(contenido)
        
        return ruta


# ============================================================================
# MENÚ PRINCIPAL
# ============================================================================

def mostrar_banner():
    """Muestra el banner principal"""
    Colores.limpiar_pantalla()
    
    banner = f"""
{Colores.ROJO}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║                  🛡️  RED GUARDIAN v1.0.0  🛡️                ║
║                                                               ║
║            HERRAMIENTA DE ANÁLISIS DE RED (CLI)              ║
║                                                               ║
║     Escanea • Analiza • Detecta • Protege • Reporta          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colores.RESET}

{Colores.AMARILLO}⚠️  AVISO LEGAL:{Colores.RESET}
   • Use esta herramienta SOLO en redes autorizadas
   • El acceso no autorizado es ILEGAL
   • Requiere consentimiento del administrador de red
   • El usuario es responsable de su uso

{Colores.VERDE}✅ Uso ético y legal solamente{Colores.RESET}

"""
    print(banner)


def mostrar_menu_principal():
    """Muestra el menú principal"""
    print(f"\n{Colores.CIAN}{Colores.NEGRITA}═══════════════════════════════════════════════════════════════{Colores.RESET}")
    print(f"{Colores.CIAN}{Colores.NEGRITA}MENÚ PRINCIPAL{Colores.RESET}")
    print(f"{Colores.CIAN}{Colores.NEGRITA}═══════════════════════════════════════════════════════════════{Colores.RESET}\n")
    
    opciones = [
        ("1", "🔍 Escanear Red Local", "escanear_red"),
        ("2", "🔓 Analizar Puertos de un Dispositivo", "analizar_puertos"),
        ("3", "⚠️  Analizar Vulnerabilidades", "analizar_vulnerabilidades"),
        ("4", "📊 Mostrar Dispositivos Detectados", "mostrar_dispositivos"),
        ("5", "📑 Generar Reportes", "generar_reportes"),
        ("6", "🔧 Información del Sistema", "info_sistema"),
        ("7", "❌ Salir", "salir"),
    ]
    
    for numero, descripcion, _ in opciones:
        print(f"  {Colores.VERDE}{numero}{Colores.RESET}. {descripcion}")
    
    print(f"\n{Colores.CIAN}{Colores.NEGRITA}═══════════════════════════════════════════════════════════════{Colores.RESET}\n")


def escanear_red():
    """Opción 1: Escanear red"""
    print(f"\n{Colores.AZUL}{Colores.NEGRITA}ESCANEO DE RED LOCAL{Colores.RESET}\n")
    
    scanner = ScannerRed()
    ip_local = scanner.obtener_ip_local()
    
    print(f"Tu IP local es: {Colores.VERDE}{ip_local}{Colores.RESET}")
    print(f"\nRangos típicos:")
    print(f"  • {Colores.AMARILLO}192.168.1.0/24{Colores.RESET} - Router típico")
    print(f"  • {Colores.AMARILLO}192.168.0.0/24{Colores.RESET} - Alternativa común")
    print(f"  • {Colores.AMARILLO}10.0.0.0/8{Colores.RESET} - Redes privadas grandes")
    
    rango = input(f"\n{Colores.CIAN}Ingresa el rango de red (ej: 192.168.1.0/24): {Colores.RESET}").strip()
    
    if not rango:
        print(f"{Colores.ROJO}❌ Rango no válido{Colores.RESET}")
        return
    
    dispositivos = scanner.escanear_red(rango)
    
    if dispositivos:
        print(f"\n{Colores.VERDE}✅ Escaneo completado!{Colores.RESET}")
        print(f"{Colores.AMARILLO}Total de dispositivos encontrados: {len(dispositivos)}{Colores.RESET}\n")
        
        # Guardar en variable global
        global dispositivos_detectados
        dispositivos_detectados = dispositivos
        
        # Mostrar tabla
        print(f"{Colores.NEGRITA}{'IP':<15} {'MAC':<17} {'Nombre':<20} {'Tipo':<25}{Colores.RESET}")
        print("─" * 77)
        for disp in dispositivos:
            print(f"{disp['ip']:<15} {disp['mac']:<17} {disp['nombre']:<20} {disp['tipo']:<25}")
    else:
        print(f"{Colores.ROJO}❌ No se encontraron dispositivos{Colores.RESET}")


def analizar_puertos():
    """Opción 2: Analizar puertos"""
    print(f"\n{Colores.AZUL}{Colores.NEGRITA}ANÁLISIS DE PUERTOS{Colores.RESET}\n")
    
    ip = input(f"{Colores.CIAN}Ingresa la IP a escanear: {Colores.RESET}").strip()
    
    if not ip:
        print(f"{Colores.ROJO}❌ IP no válida{Colores.RESET}")
        return
    
    analizador = AnalizadorPuertos()
    puertos = analizador.escanear_puertos(ip)
    
    if puertos:
        print(f"\n{Colores.VERDE}✅ Escaneo completado!{Colores.RESET}")
        print(f"{Colores.AMARILLO}Puertos abiertos encontrados: {len(puertos)}{Colores.RESET}\n")
        
        print(f"{Colores.NEGRITA}{'Puerto':<10} {'Servicio':<20} {'Estado':<15}{Colores.RESET}")
        print("─" * 45)
        for puerto_info in puertos:
            print(f"{puerto_info['puerto']:<10} {puerto_info['servicio']:<20} {puerto_info['estado']:<15}")
        
        # Guardar en variable global
        global puertos_detectados
        puertos_detectados[ip] = puertos
    else:
        print(f"{Colores.AMARILLO}ℹ️  No se encontraron puertos abiertos (o están filtrados){Colores.RESET}")


def analizar_vulnerabilidades():
    """Opción 3: Analizar vulnerabilidades"""
    print(f"\n{Colores.AZUL}{Colores.NEGRITA}ANÁLISIS DE VULNERABILIDADES{Colores.RESET}\n")
    
    if not dispositivos_detectados:
        print(f"{Colores.ROJO}❌ Primero debes escanear la red{Colores.RESET}")
        return
    
    print(f"Analizando {len(dispositivos_detectados)} dispositivos...\n")
    
    detector = DetectorVulnerabilidades()
    analizador = AnalizadorPuertos()
    todas_vulnerabilidades = []
    
    for dispositivo in dispositivos_detectados:
        ip = dispositivo['ip']
        print(f"  🔍 Analizando {ip}...")
        
        # Escanear puertos
        puertos = analizador.escanear_puertos(ip)
        
        # Detectar vulnerabilidades
        vulns = detector.detectar_vulnerabilidades(ip, puertos)
        todas_vulnerabilidades.extend(vulns)
    
    if todas_vulnerabilidades:
        print(f"\n{Colores.ROJO}⚠️  VULNERABILIDADES DETECTADAS:{Colores.RESET}\n")
        
        # Agrupar por nivel de riesgo
        alto_riesgo = [v for v in todas_vulnerabilidades if v['riesgo'] == 'Alto']
        medio_riesgo = [v for v in todas_vulnerabilidades if v['riesgo'] == 'Medio']
        bajo_riesgo = [v for v in todas_vulnerabilidades if v['riesgo'] == 'Bajo']
        
        if alto_riesgo:
            print(f"{Colores.ROJO}{Colores.NEGRITA}🔴 ALTO RIESGO ({len(alto_riesgo)}):{Colores.RESET}")
            for v in alto_riesgo:
                print(f"   • {v['dispositivo']} - {v['servicio']} (Puerto {v['puerto']})")
                print(f"     └─ {v['descripcion']}\n")
        
        if medio_riesgo:
            print(f"{Colores.AMARILLO}{Colores.NEGRITA}🟡 RIESGO MEDIO ({len(medio_riesgo)}):{Colores.RESET}")
            for v in medio_riesgo:
                print(f"   • {v['dispositivo']} - {v['servicio']} (Puerto {v['puerto']})")
                print(f"     └─ {v['descripcion']}\n")
        
        if bajo_riesgo:
            print(f"{Colores.VERDE}{Colores.NEGRITA}🟢 BAJO RIESGO ({len(bajo_riesgo)}):{Colores.RESET}")
            for v in bajo_riesgo:
                print(f"   • {v['dispositivo']} - {v['servicio']} (Puerto {v['puerto']})")
                print(f"     └─ {v['descripcion']}\n")
        
        # Guardar en variable global
        global vulnerabilidades_detectadas
        vulnerabilidades_detectadas = todas_vulnerabilidades
        
        # Score general
        score = detector.calcular_score_seguridad(todas_vulnerabilidades)
        print(f"\n{Colores.NEGRITA}Score de Seguridad General: {score}/100{Colores.RESET}")
    else:
        print(f"{Colores.VERDE}✅ No se detectaron vulnerabilidades{Colores.RESET}")


def mostrar_dispositivos():
    """Opción 4: Mostrar dispositivos detectados"""
    print(f"\n{Colores.AZUL}{Colores.NEGRITA}DISPOSITIVOS DETECTADOS{Colores.RESET}\n")
    
    if not dispositivos_detectados:
        print(f"{Colores.ROJO}❌ No hay dispositivos detectados{Colores.RESET}")
        return
    
    print(f"Total: {Colores.AMARILLO}{len(dispositivos_detectados)}{Colores.RESET} dispositivos\n")
    
    print(f"{Colores.NEGRITA}{'IP':<15} {'MAC':<17} {'Nombre':<20} {'Tipo':<25}{Colores.RESET}")
    print("─" * 77)
    
    for disp in dispositivos_detectados:
        print(f"{disp['ip']:<15} {disp['mac']:<17} {disp['nombre']:<20} {disp['tipo']:<25}")


def generar_reportes():
    """Opción 5: Generar reportes"""
    print(f"\n{Colores.AZUL}{Colores.NEGRITA}GENERACIÓN DE REPORTES{Colores.RESET}\n")
    
    if not dispositivos_detectados:
        print(f"{Colores.ROJO}❌ No hay datos para generar reportes{Colores.RESET}")
        return
    
    generador = GeneradorReportes()
    
    print("Selecciona formato de reporte:")
    print(f"  1. {Colores.VERDE}JSON{Colores.RESET} (para aplicaciones)")
    print(f"  2. {Colores.VERDE}CSV{Colores.RESET} (para Excel/Sheets)")
    print(f"  3. {Colores.VERDE}TXT{Colores.RESET} (texto plano)")
    
    opcion = input(f"\n{Colores.CIAN}Selecciona opción (1-3): {Colores.RESET}").strip()
    
    datos = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_dispositivos": len(dispositivos_detectados),
        "dispositivos": dispositivos_detectados,
        "vulnerabilidades": vulnerabilidades_detectados,
    }
    
    if opcion == "1":
        ruta = generador.generar_json(datos)
        print(f"\n{Colores.VERDE}✅ Reporte JSON generado:{Colores.RESET}")
    
    elif opcion == "2":
        ruta = generador.generar_csv(dispositivos_detectados)
        print(f"\n{Colores.VERDE}✅ Reporte CSV generado:{Colores.RESET}")
    
    elif opcion == "3":
        contenido = generar_contenido_txt(datos)
        ruta = generador.generar_txt(contenido)
        print(f"\n{Colores.VERDE}✅ Reporte TXT generado:{Colores.RESET}")
    
    else:
        print(f"{Colores.ROJO}❌ Opción no válida{Colores.RESET}")
        return
    
    print(f"   📁 {ruta}")


def generar_contenido_txt(datos):
    """Genera contenido de reporte en texto"""
    contenido = f"""
{'='*70}
REPORTE DE SEGURIDAD DE RED - RED GUARDIAN v1.0.0
{'='*70}

Fecha: {datos['timestamp']}
Total de dispositivos: {datos['total_dispositivos']}

{'='*70}
DISPOSITIVOS DETECTADOS
{'='*70}

"""
    
    contenido += f"{'IP':<15} {'MAC':<17} {'NOMBRE':<20} {'TIPO':<25}\n"
    contenido += "─" * 77 + "\n"
    
    for disp in datos['dispositivos']:
        contenido += f"{disp['ip']:<15} {disp['mac']:<17} {disp['nombre']:<20} {disp['tipo']:<25}\n"
    
    if datos['vulnerabilidades']:
        contenido += f"\n{'='*70}\nVULNERABILIDADES DETECTADAS\n{'='*70}\n\n"
        
        for vuln in datos['vulnerabilidades']:
            contenido += f"Dispositivo: {vuln['dispositivo']}\n"
            contenido += f"Servicio: {vuln['servicio']}\n"
            contenido += f"Puerto: {vuln['puerto']}\n"
            contenido += f"Riesgo: {vuln['riesgo']}\n"
            contenido += f"Descripción: {vuln['descripcion']}\n"
            contenido += "─" * 70 + "\n"
    
    contenido += f"\n{'='*70}\n"
    contenido += "⚠️  AVISO LEGAL\n"
    contenido += "Este reporte contiene información sensible de seguridad.\n"
    contenido += "Manténlo confidencial y en lugar seguro.\n"
    contenido += "Use solo para propósitos autorizados.\n"
    contenido += f"{'='*70}\n"
    
    return contenido


def info_sistema():
    """Opción 6: Información del sistema"""
    print(f"\n{Colores.AZUL}{Colores.NEGRITA}INFORMACIÓN DEL SISTEMA{Colores.RESET}\n")
    
    scanner = ScannerRed()
    
    print(f"IP Local: {Colores.VERDE}{scanner.obtener_ip_local()}{Colores.RESET}")
    print(f"Hostname: {Colores.VERDE}{socket.gethostname()}{Colores.RESET}")
    print(f"Plataforma: {Colores.VERDE}{sys.platform}{Colores.RESET}")
    print(f"Versión Python: {Colores.VERDE}{sys.version.split()[0]}{Colores.RESET}")
    
    if SCAPY_AVAILABLE:
        print(f"Scapy: {Colores.VERDE}✓ Instalado{Colores.RESET}")
    else:
        print(f"Scapy: {Colores.ROJO}✗ No instalado{Colores.RESET}")
    
    if PSUTIL_AVAILABLE:
        print(f"psutil: {Colores.VERDE}✓ Instalado{Colores.RESET}")
        print(f"CPU: {Colores.VERDE}{psutil.cpu_count()} cores{Colores.RESET}")
        ram = psutil.virtual_memory()
        print(f"RAM: {Colores.VERDE}{ram.total / (1024**3):.2f} GB{Colores.RESET}")
    else:
        print(f"psutil: {Colores.ROJO}✗ No instalado{Colores.RESET}")


def menu_principal_loop():
    """Loop principal del menú"""
    while True:
        mostrar_menu_principal()
        
        opcion = input(f"{Colores.CIAN}Selecciona una opción: {Colores.RESET}").strip()
        
        if opcion == "1":
            escanear_red()
        elif opcion == "2":
            analizar_puertos()
        elif opcion == "3":
            analizar_vulnerabilidades()
        elif opcion == "4":
            mostrar_dispositivos()
        elif opcion == "5":
            generar_reportes()
        elif opcion == "6":
            info_sistema()
        elif opcion == "7":
            print(f"\n{Colores.AMARILLO}👋 ¡Hasta luego!{Colores.RESET}\n")
            break
        else:
            print(f"{Colores.ROJO}❌ Opción no válida{Colores.RESET}")
        
        input(f"\n{Colores.GRIS}Presiona Enter para continuar...{Colores.RESET}")


# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

# Variables globales
dispositivos_detectados = []
puertos_detectados = {}
vulnerabilidades_detectados = []

def main():
    """Función principal"""
    if not SCAPY_AVAILABLE:
        print(f"{Colores.ROJO}❌ ERROR: Scapy no está instalado{Colores.RESET}")
        print(f"\nInstálalo con: {Colores.VERDE}pip install scapy{Colores.RESET}\n")
        return
    
    mostrar_banner()
    
    try:
        menu_principal_loop()
    except KeyboardInterrupt:
        print(f"\n\n{Colores.AMARILLO}⚠️  Programa interrumpido por el usuario{Colores.RESET}\n")
    except Exception as e:
        print(f"\n{Colores.ROJO}❌ Error: {str(e)}{Colores.RESET}\n")


if __name__ == "__main__":
    main()
