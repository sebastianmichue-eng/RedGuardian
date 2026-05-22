#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RedGuardian - Herramienta Profesional de Análisis de Red
Versión: 1.0.0
Autor: Red Guardian Development Team
Licencia: MIT
Descripción: Sistema completo de escaneo, monitoreo y análisis de seguridad de redes
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import json
import csv
import os
import sys
import re
import socket
import subprocess
import platform
from datetime import datetime
from collections import defaultdict
import struct
import textwrap

try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, send, sniff, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    messagebox.showwarning("Advertencia", "Scapy no está instalado. Instálalo con: pip install scapy")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ============================================================================
# MÓDULO 1: ESCANEO DE RED
# ============================================================================

class NetworkScanner:
    """Módulo de escaneo de red y detección de dispositivos"""
    
    def __init__(self):
        self.devices = []
        self.network_range = None
        self.scan_active = False
        
    def get_local_ip(self):
        """Obtiene la IP local del dispositivo"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            return "127.0.0.1"
    
    def get_mac_address(self, ip):
        """Obtiene la dirección MAC de una IP usando ARP"""
        try:
            if not SCAPY_AVAILABLE:
                return "Desconocida"
            
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered, unanswered = srp(arp_request_broadcast, timeout=2, verbose=False)
            
            for sent, received in answered:
                return received.hwsrc
            return "Desconocida"
        except Exception:
            return "Desconocida"
    
    def get_device_name(self, ip):
        """Obtiene el nombre del dispositivo (hostname)"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Desconocido"
    
    def detect_device_type(self, ip, mac):
        """Detecta el tipo de dispositivo basado en la dirección MAC"""
        mac_vendors = {
            "00:50:F2": "Microsoft",
            "00:0A:95": "Apple",
            "00:11:95": "Apple",
            "00:1A:A0": "Apple",
            "08:00:27": "Oracle VirtualBox",
            "52:54:00": "QEMU",
            "DC:A6:32": "Raspberry Pi",
            "B8:27:EB": "Raspberry Pi",
            "28:CE:F2": "Cisco",
            "00:04:4B": "3Com",
            "08:00:69": "Silicon Graphics",
            "00:30:48": "Cisco Systems",
        }
        
        mac_prefix = mac[:8].upper()
        for prefix, vendor in mac_vendors.items():
            if mac.upper().startswith(prefix):
                return vendor
        
        return "Dispositivo Genérico"
    
    def scan_network(self, network_range, callback=None):
        """Escanea la red en busca de dispositivos conectados"""
        self.scan_active = True
        self.devices = []
        
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy no disponible"}
        
        try:
            arp_request = ARP(pdst=network_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            answered, unanswered = srp(arp_request_broadcast, timeout=3, verbose=False)
            
            for sent, received in answered:
                if not self.scan_active:
                    break
                
                ip = received.psrc
                mac = received.hwsrc
                hostname = self.get_device_name(ip)
                device_type = self.detect_device_type(ip, mac)
                
                device = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "tipo": device_type,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.devices.append(device)
                
                if callback:
                    callback(device)
            
            return {"dispositivos": self.devices, "total": len(self.devices)}
        
        except Exception as e:
            return {"error": str(e)}
    
    def stop_scan(self):
        """Detiene el escaneo"""
        self.scan_active = False


# ============================================================================
# MÓDULO 2: ANÁLISIS DE PUERTOS
# ============================================================================

class PortAnalyzer:
    """Módulo de análisis de puertos y servicios"""
    
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
    
    def __init__(self):
        self.scan_active = False
    
    def scan_ports(self, ip, timeout=2, callback=None):
        """Escanea puertos abiertos en una IP"""
        open_ports = []
        
        try:
            for port in self.PUERTOS_COMUNES.keys():
                if not self.scan_active:
                    continue
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                try:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        service = self.PUERTOS_COMUNES.get(port, "Desconocido")
                        open_ports.append({
                            "puerto": port,
                            "servicio": service,
                            "estado": "Abierto"
                        })
                        if callback:
                            callback(port, service)
                except:
                    pass
                finally:
                    sock.close()
        
        except Exception as e:
            return {"error": str(e)}
        
        return open_ports
    
    def scan_ports_threaded(self, ip, callback=None):
        """Escanea puertos en hilo separado"""
        self.scan_active = True
        return self.scan_ports(ip, callback=callback)
    
    def stop_scan(self):
        """Detiene el escaneo de puertos"""
        self.scan_active = False


# ============================================================================
# MÓDULO 3: ANÁLISIS DE TRÁFICO
# ============================================================================

class TrafficAnalyzer:
    """Módulo de análisis de tráfico de red"""
    
    def __init__(self):
        self.packets_captured = []
        self.is_sniffing = False
    
    def analyze_packet(self, packet):
        """Analiza un paquete de red capturado"""
        packet_data = {
            "timestamp": datetime.now().isoformat(),
            "protocolo": "Desconocido",
            "origen": "N/A",
            "destino": "N/A",
            "tamaño": len(packet)
        }
        
        if IP in packet:
            packet_data["protocolo"] = "IP"
            packet_data["origen"] = packet[IP].src
            packet_data["destino"] = packet[IP].dst
            
            if TCP in packet:
                packet_data["protocolo"] = "TCP"
                packet_data["puerto_origen"] = packet[TCP].sport
                packet_data["puerto_destino"] = packet[TCP].dport
            elif UDP in packet:
                packet_data["protocolo"] = "UDP"
                packet_data["puerto_origen"] = packet[UDP].sport
                packet_data["puerto_destino"] = packet[UDP].dport
        
        self.packets_captured.append(packet_data)
        return packet_data
    
    def get_statistics(self):
        """Obtiene estadísticas de tráfico capturado"""
        if not self.packets_captured:
            return {}
        
        stats = {
            "total_paquetes": len(self.packets_captured),
            "tamaño_promedio": sum(p.get("tamaño", 0) for p in self.packets_captured) // len(self.packets_captured),
            "protocolos": defaultdict(int),
            "ips_origen": defaultdict(int),
            "ips_destino": defaultdict(int)
        }
        
        for packet in self.packets_captured:
            stats["protocolos"][packet.get("protocolo")] += 1
            stats["ips_origen"][packet.get("origen")] += 1
            stats["ips_destino"][packet.get("destino")] += 1
        
        return stats


# ============================================================================
# MÓDULO 4: DETECCIÓN DE VULNERABILIDADES
# ============================================================================

class VulnerabilityDetector:
    """Módulo de detección de vulnerabilidades"""
    
    VULNERABILIDADES_CONOCIDAS = {
        "SMB": {"puerto": 445, "riesgo": "Alto", "descripcion": "Acceso a recursos compartidos sin protección"},
        "Telnet": {"puerto": 23, "riesgo": "Alto", "descripcion": "Protocolo no cifrado, susceptible a interceptación"},
        "FTP": {"puerto": 21, "riesgo": "Alto", "descripcion": "Protocolo no cifrado para transferencia de archivos"},
        "HTTP": {"puerto": 80, "riesgo": "Medio", "descripcion": "Conexión no cifrada"},
        "SSH": {"puerto": 22, "riesgo": "Bajo", "descripcion": "Protocolo seguro de acceso remoto"},
        "DNS": {"puerto": 53, "riesgo": "Medio", "descripcion": "Posible DNS spoofing o envenenamiento de caché"},
    }
    
    def detect_vulnerabilities(self, dispositivo, puertos_abiertos):
        """Detecta vulnerabilidades basadas en puertos abiertos"""
        vulnerabilidades = []
        
        for puerto_info in puertos_abiertos:
            puerto = puerto_info["puerto"]
            servicio = puerto_info["servicio"]
            
            if servicio in self.VULNERABILIDADES_CONOCIDAS:
                vuln = self.VULNERABILIDADES_CONOCIDAS[servicio]
                vulnerabilidades.append({
                    "servicio": servicio,
                    "puerto": puerto,
                    "riesgo": vuln["riesgo"],
                    "descripcion": vuln["descripcion"],
                    "dispositivo": dispositivo
                })
        
        return vulnerabilidades
    
    def generate_security_score(self, vulnerabilidades):
        """Genera un score de seguridad de 0-100"""
        if not vulnerabilidades:
            return 100
        
        riesgo_puntos = {"Alto": 30, "Medio": 15, "Bajo": 5}
        puntos_perdidos = sum(riesgo_puntos.get(v["riesgo"], 0) for v in vulnerabilidades)
        
        score = max(0, 100 - puntos_perdidos)
        return score


# ============================================================================
# MÓDULO 5: GENERACIÓN DE REPORTES
# ============================================================================

class ReportGenerator:
    """Módulo de generación de reportes"""
    
    def __init__(self):
        self.reports_dir = "reportes_redguardian"
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def generate_json_report(self, data, filename=None):
        """Genera reporte en formato JSON"""
        if not filename:
            filename = f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def generate_csv_report(self, devices, filename=None):
        """Genera reporte en formato CSV"""
        if not filename:
            filename = f"dispositivos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        if devices:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=devices[0].keys())
                writer.writeheader()
                writer.writerows(devices)
        
        return filepath
    
    def generate_html_report(self, data, filename=None):
        """Genera reporte en formato HTML"""
        if not filename:
            filename = f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>RedGuardian - Reporte de Seguridad</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }}
                h1 {{ color: #333; margin-bottom: 20px; text-align: center; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
                h2 {{ color: #667eea; margin-top: 30px; margin-bottom: 15px; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
                th {{ background: #667eea; color: white; padding: 12px; text-align: left; }}
                td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
                tr:hover {{ background: #f5f5f5; }}
                .alert {{ padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .alert-high {{ background: #ffebee; border-left: 4px solid #f44336; color: #c62828; }}
                .alert-medium {{ background: #fff3e0; border-left: 4px solid #ff9800; color: #e65100; }}
                .alert-low {{ background: #e8f5e9; border-left: 4px solid #4caf50; color: #2e7d32; }}
                .timestamp {{ color: #666; font-size: 0.9em; }}
                footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ RedGuardian - Reporte de Seguridad de Red</h1>
                <p class="timestamp">Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>Resumen</h2>
                <p>Dispositivos encontrados: <strong>{len(data.get("dispositivos", []))}</strong></p>
                <p>Vulnerabilidades detectadas: <strong>{len(data.get("vulnerabilidades", []))}</strong></p>
                
                <h2>Dispositivos Conectados</h2>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>MAC</th>
                        <th>Nombre</th>
                        <th>Tipo</th>
                    </tr>
        """
        
        for device in data.get("dispositivos", []):
            html_content += f"""
                    <tr>
                        <td>{device.get('ip', 'N/A')}</td>
                        <td>{device.get('mac', 'N/A')}</td>
                        <td>{device.get('hostname', 'Desconocido')}</td>
                        <td>{device.get('tipo', 'N/A')}</td>
                    </tr>
            """
        
        html_content += """
                </table>
                
                <h2>Vulnerabilidades Detectadas</h2>
        """
        
        for vuln in data.get("vulnerabilidades", []):
            riesgo_class = f"alert-{vuln.get('riesgo', 'Bajo').lower()}"
            html_content += f"""
                <div class="alert {riesgo_class}">
                    <strong>{vuln.get('servicio', 'N/A')}</strong> - Puerto {vuln.get('puerto', 'N/A')}<br>
                    Riesgo: {vuln.get('riesgo', 'N/A')}<br>
                    {vuln.get('descripcion', 'Sin descripción')}
                </div>
            """
        
        html_content += f"""
                <footer>
                    <p>RedGuardian v1.0.0 - Herramienta Profesional de Análisis de Red</p>
                    <p>Uso ético y legal solamente. Requiere autorización del administrador de red.</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath


# ============================================================================
# MÓDULO 6: INTERFAZ GRÁFICA (GUI)
# ============================================================================

class RedGuardianGUI:
    """Interfaz gráfica de usuario para RedGuardian"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ RedGuardian - Análisis Profesional de Red v1.0.0")
        self.root.geometry("1400x900")
        self.root.configure(bg="#f0f0f0")
        
        # Inicializar módulos
        self.scanner = NetworkScanner()
        self.port_analyzer = PortAnalyzer()
        self.traffic_analyzer = TrafficAnalyzer()
        self.vulnerability_detector = VulnerabilityDetector()
        self.report_generator = ReportGenerator()
        
        self.scan_thread = None
        self.devices_data = []
        self.vulnerabilities_data = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Configura la interfaz gráfica"""
        # Barra de menú superior
        self.create_menu_bar()
        
        # Frame principal con tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Escaneo de Red
        self.create_scan_tab()
        
        # Tab 2: Análisis de Puertos
        self.create_port_tab()
        
        # Tab 3: Análisis de Tráfico
        self.create_traffic_tab()
        
        # Tab 4: Vulnerabilidades
        self.create_vulnerability_tab()
        
        # Tab 5: Reportes
        self.create_reports_tab()
        
        # Tab 6: Información
        self.create_info_tab()
    
    def create_menu_bar(self):
        """Crea la barra de menú"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Menú Archivo
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Archivo", menu=file_menu)
        file_menu.add_command(label="Salir", command=self.root.quit)
        
        # Menú Ayuda
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayuda", menu=help_menu)
        help_menu.add_command(label="Acerca de", command=self.show_about)
    
    def create_scan_tab(self):
        """Crea la pestaña de escaneo de red"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📡 Escaneo de Red")
        
        # Panel superior: entrada de rango de red
        top_frame = ttk.LabelFrame(frame, text="Configuración de Escaneo", padding=10)
        top_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(top_frame, text="Rango de Red (ej. 192.168.1.0/24):").pack(side=tk.LEFT, padx=5)
        
        self.network_entry = ttk.Entry(top_frame, width=25)
        self.network_entry.pack(side=tk.LEFT, padx=5)
        self.network_entry.insert(0, "192.168.1.0/24")
        
        self.scan_button = ttk.Button(top_frame, text="🔍 Iniciar Escaneo", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(top_frame, text="⏹️ Detener", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Barra de progreso
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(top_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        # Panel central: resultados
        result_frame = ttk.LabelFrame(frame, text="Dispositivos Detectados", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tabla de dispositivos
        columns = ("IP", "MAC", "Hostname", "Tipo", "Timestamp")
        self.scan_tree = ttk.Treeview(result_frame, columns=columns, height=20)
        self.scan_tree.column("#0", width=0, stretch=tk.NO)
        self.scan_tree.column("IP", anchor=tk.W, width=120)
        self.scan_tree.column("MAC", anchor=tk.W, width=130)
        self.scan_tree.column("Hostname", anchor=tk.W, width=150)
        self.scan_tree.column("Tipo", anchor=tk.W, width=120)
        self.scan_tree.column("Timestamp", anchor=tk.W, width=170)
        
        self.scan_tree.heading("#0", text="", anchor=tk.W)
        self.scan_tree.heading("IP", text="IP", anchor=tk.W)
        self.scan_tree.heading("MAC", text="MAC", anchor=tk.W)
        self.scan_tree.heading("Hostname", text="Hostname", anchor=tk.W)
        self.scan_tree.heading("Tipo", text="Tipo", anchor=tk.W)
        self.scan_tree.heading("Timestamp", text="Timestamp", anchor=tk.W)
        
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.scan_tree.yview)
        self.scan_tree.configure(yscroll=scrollbar.set)
        self.scan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Panel inferior: acciones
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="🔍 Analizar Puertos", command=self.analyze_selected_ports).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="💾 Exportar CSV", command=self.export_devices_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🗑️ Limpiar", command=self.clear_scan_results).pack(side=tk.LEFT, padx=5)
    
    def create_port_tab(self):
        """Crea la pestaña de análisis de puertos"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔓 Análisis de Puertos")
        
        # Panel superior
        top_frame = ttk.LabelFrame(frame, text="Configuración de Escaneo de Puertos", padding=10)
        top_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(top_frame, text="Dirección IP:").pack(side=tk.LEFT, padx=5)
        
        self.port_ip_entry = ttk.Entry(top_frame, width=20)
        self.port_ip_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(top_frame, text="🔍 Escanear Puertos", command=self.start_port_scan).pack(side=tk.LEFT, padx=5)
        
        # Resultados
        result_frame = ttk.LabelFrame(frame, text="Puertos Abiertos", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("Puerto", "Servicio", "Estado")
        self.port_tree = ttk.Treeview(result_frame, columns=columns, height=20)
        self.port_tree.column("#0", width=0, stretch=tk.NO)
        self.port_tree.column("Puerto", anchor=tk.W, width=100)
        self.port_tree.column("Servicio", anchor=tk.W, width=200)
        self.port_tree.column("Estado", anchor=tk.W, width=150)
        
        self.port_tree.heading("#0", text="", anchor=tk.W)
        self.port_tree.heading("Puerto", text="Puerto", anchor=tk.W)
        self.port_tree.heading("Servicio", text="Servicio", anchor=tk.W)
        self.port_tree.heading("Estado", text="Estado", anchor=tk.W)
        
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.port_tree.yview)
        self.port_tree.configure(yscroll=scrollbar.set)
        self.port_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_traffic_tab(self):
        """Crea la pestaña de análisis de tráfico"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📊 Análisis de Tráfico")
        
        info_label = ttk.Label(frame, text="Monitoreo de Tráfico - Estadísticas en Tiempo Real", font=("Arial", 12, "bold"))
        info_label.pack(padx=10, pady=10)
        
        # Panel de estadísticas
        stats_frame = ttk.LabelFrame(frame, text="Estadísticas de Red", padding=10)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.traffic_text = scrolledtext.ScrolledText(stats_frame, height=25, width=80)
        self.traffic_text.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="📈 Mostrar Estadísticas", command=self.show_traffic_stats).pack(side=tk.LEFT, padx=5)
    
    def create_vulnerability_tab(self):
        """Crea la pestaña de vulnerabilidades"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="⚠️ Vulnerabilidades")
        
        info_label = ttk.Label(frame, text="Análisis de Vulnerabilidades Detectadas", font=("Arial", 12, "bold"))
        info_label.pack(padx=10, pady=10)
        
        # Panel de vulnerabilidades
        vuln_frame = ttk.LabelFrame(frame, text="Vulnerabilidades Encontradas", padding=10)
        vuln_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("Dispositivo", "Servicio", "Puerto", "Riesgo", "Descripción")
        self.vuln_tree = ttk.Treeview(vuln_frame, columns=columns, height=20)
        self.vuln_tree.column("#0", width=0, stretch=tk.NO)
        self.vuln_tree.column("Dispositivo", anchor=tk.W, width=120)
        self.vuln_tree.column("Servicio", anchor=tk.W, width=100)
        self.vuln_tree.column("Puerto", anchor=tk.W, width=80)
        self.vuln_tree.column("Riesgo", anchor=tk.W, width=80)
        self.vuln_tree.column("Descripción", anchor=tk.W, width=300)
        
        self.vuln_tree.heading("#0", text="", anchor=tk.W)
        self.vuln_tree.heading("Dispositivo", text="Dispositivo", anchor=tk.W)
        self.vuln_tree.heading("Servicio", text="Servicio", anchor=tk.W)
        self.vuln_tree.heading("Puerto", text="Puerto", anchor=tk.W)
        self.vuln_tree.heading("Riesgo", text="Riesgo", anchor=tk.W)
        self.vuln_tree.heading("Descripción", text="Descripción", anchor=tk.W)
        
        scrollbar = ttk.Scrollbar(vuln_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscroll=scrollbar.set)
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="🔍 Analizar Vulnerabilidades", command=self.analyze_vulnerabilities).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📋 Generar Reporte", command=self.generate_vulnerability_report).pack(side=tk.LEFT, padx=5)
    
    def create_reports_tab(self):
        """Crea la pestaña de reportes"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📑 Reportes")
        
        info_label = ttk.Label(frame, text="Generación de Reportes de Seguridad", font=("Arial", 12, "bold"))
        info_label.pack(padx=10, pady=10)
        
        # Panel de opciones
        options_frame = ttk.LabelFrame(frame, text="Opciones de Reporte", padding=10)
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(options_frame, text="📄 Generar Reporte JSON", command=lambda: self.generate_report("json")).pack(side=tk.LEFT, padx=5)
        ttk.Button(options_frame, text="📊 Generar Reporte CSV", command=lambda: self.generate_report("csv")).pack(side=tk.LEFT, padx=5)
        ttk.Button(options_frame, text="🌐 Generar Reporte HTML", command=lambda: self.generate_report("html")).pack(side=tk.LEFT, padx=5)
        ttk.Button(options_frame, text="📂 Abrir Carpeta de Reportes", command=self.open_reports_folder).pack(side=tk.LEFT, padx=5)
        
        # Panel de información
        info_frame = ttk.LabelFrame(frame, text="Información de Reportes Generados", padding=10)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.reports_text = scrolledtext.ScrolledText(info_frame, height=20, width=80)
        self.reports_text.pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(frame, text="🔄 Actualizar Lista de Reportes", command=self.refresh_reports_list).pack(padx=10, pady=10)
    
    def create_info_tab(self):
        """Crea la pestaña de información"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="ℹ️ Información")
        
        info_text = scrolledtext.ScrolledText(frame, height=30, width=100)
        info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        info_content = """
╔════════════════════════════════════════════════════════════════╗
║                     RedGuardian v1.0.0                        ║
║          Herramienta Profesional de Análisis de Red           ║
╚════════════════════════════════════════════════════════════════╝

📋 DESCRIPCIÓN
RedGuardian es una herramienta completa de análisis y monitoreo de redes 
que detecta dispositivos conectados, identifica puertos abiertos, analiza 
tráfico de red y genera reportes detallados sobre la seguridad de la red.

🎯 FUNCIONALIDADES PRINCIPALES

1. 📡 Escaneo de Red
   • Detecta dispositivos conectados en la red local
   • Obtiene direcciones IP y MAC de cada dispositivo
   • Identifica nombres de host (hostnames)
   • Clasifica dispositivos por tipo (PCs, servidores, IoT, etc.)

2. 🔓 Análisis de Puertos
   • Escanea puertos abiertos en dispositivos detectados
   • Identifica servicios activos en cada puerto
   • Determina el estado de cada puerto (Abierto/Cerrado)

3. 📊 Análisis de Tráfico
   • Monitorea tráfico de red en tiempo real
   • Analiza protocolos utilizados
   • Genera estadísticas de uso de red

4. ⚠️ Detección de Vulnerabilidades
   • Identifica puertos y servicios peligrosos
   • Calcula score de seguridad para cada dispositivo
   • Clasifica vulnerabilidades por nivel de riesgo (Alto/Medio/Bajo)

5. 📑 Generación de Reportes
   • Exporta datos en formatos: JSON, CSV, HTML
   • Incluye detalles de dispositivos y vulnerabilidades
   • Proporciona recomendaciones de seguridad

🔒 CONSIDERACIONES DE SEGURIDAD Y ÉTICA

⚠️ IMPORTANTE: Este programa debe usarse únicamente:
   ✓ Con autorización expresa del administrador de red
   ✓ Dentro del ámbito de la red autorizada
   ✓ Para fines legítimos de ciberseguridad
   ✓ Respetando la privacidad de los usuarios

PROHIBIDO:
   ✗ Usar sin autorización del administrador
   ✗ Escanear redes ajenas sin permiso legal
   ✗ Almacenar o distribuir información de usuarios sin consentimiento
   ✗ Usar para propósitos maliciosos o ilegales

📋 REQUISITOS TÉCNICOS

Sistema Operativo:
   • Windows 7/10/11
   • macOS 10.12+
   • Linux (Ubuntu 18.04+, Debian 9+, Fedora 25+)

Dependencias Python:
   • Python 3.6 o superior
   • Scapy (análisis de paquetes)
   • Tkinter (interfaz gráfica)
   • psutil (información de sistema)
   • nmap (escaneo de red avanzado - opcional)

Permisos Requeridos:
   • Acceso de administrador/sudo para escaneo de red
   • Acceso a la red local

💾 INSTALACIÓN

1. Instalar Python 3.x desde https://www.python.org

2. Instalar dependencias:
   pip install scapy psutil

3. En Linux/macOS, ejecutar con sudo:
   sudo python3 redguardian.py

4. En Windows, ejecutar como Administrador

🚀 USO BÁSICO

1. Especificar rango de red (ej. 192.168.1.0/24)
2. Hacer clic en "Iniciar Escaneo"
3. Esperar resultados de dispositivos conectados
4. Seleccionar dispositivo y analizar puertos
5. Revisar vulnerabilidades detectadas
6. Generar reporte en formato deseado

📊 INTERPRETACIÓN DE RESULTADOS

Score de Seguridad:
   • 90-100: Muy seguro - Pocos riesgos detectados
   • 70-89: Seguro - Algunos riesgos menores
   • 50-69: Moderado - Vulnerabilidades detectadas
   • 30-49: Riesgo - Múltiples vulnerabilidades
   • 0-29: Crítico - Riesgos graves detectados

Niveles de Riesgo:
   • 🔴 ALTO: Requiere atención inmediata
   • 🟡 MEDIO: Revisar y considerar mitigación
   • 🟢 BAJO: Monitorear

👨‍💼 SOPORTE Y AYUDA

Para reportar bugs o sugerencias:
   • Contactar al administrador de red
   • Revisar documentación técnica
   • Consultar guía de solución de problemas

📜 LICENCIA

RedGuardian v1.0.0
Licencia: MIT
Año: 2024
© Red Guardian Development Team

Uso sujeto a cumplimiento de leyes de ciberseguridad locales 
e internacionales aplicables.

═══════════════════════════════════════════════════════════════

⚡ RECOMENDACIONES DE SEGURIDAD

✓ Ejecutar escaneos durante horas no laborales si es posible
✓ Mantener registros de escaneos realizados
✓ Revisar reportes con administrador de red
✓ Implementar recomendaciones de seguridad detectadas
✓ Realizar escaneos periódicos (mensual/trimestral)
✓ Actualizar software regularmente
✓ Configurar firewalls y controles de acceso
✓ Usar contraseñas fuertes y cambiarlas regularmente

═══════════════════════════════════════════════════════════════
"""
        info_text.insert(1.0, info_content)
        info_text.config(state=tk.DISABLED)
    
    # ========== MÉTODOS DE ESCANEO ==========
    
    def start_scan(self):
        """Inicia el escaneo de red"""
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy no está instalado. Instálalo con: pip install scapy")
            return
        
        network_range = self.network_entry.get().strip()
        if not network_range:
            messagebox.showwarning("Advertencia", "Ingresa un rango de red válido")
            return
        
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.devices_data = []
        
        self.scan_thread = threading.Thread(target=self._scan_network_thread, args=(network_range,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def _scan_network_thread(self, network_range):
        """Ejecuta el escaneo en un hilo separado"""
        try:
            result = self.scanner.scan_network(network_range, callback=self._add_device_to_tree)
            
            if "error" in result:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Error en escaneo: {result['error']}"))
            else:
                self.devices_data = result.get("dispositivos", [])
                total = result.get("total", 0)
                self.root.after(0, lambda: messagebox.showinfo("Éxito", f"Escaneo completado. {total} dispositivos encontrados."))
        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Error durante el escaneo: {str(e)}"))
        
        finally:
            self.root.after(0, self._scan_complete)
    
    def _add_device_to_tree(self, device):
        """Añade un dispositivo a la tabla de resultados"""
        self.root.after(0, lambda: self._insert_device_row(device))
    
    def _insert_device_row(self, device):
        """Inserta una fila en la tabla"""
        values = (
            device.get("ip"),
            device.get("mac"),
            device.get("hostname"),
            device.get("tipo"),
            device.get("timestamp")
        )
        self.scan_tree.insert("", tk.END, values=values)
    
    def _scan_complete(self):
        """Cuando el escaneo se completa"""
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_var.set(100)
    
    def stop_scan(self):
        """Detiene el escaneo"""
        self.scanner.stop_scan()
        self.stop_button.config(state=tk.DISABLED)
    
    def clear_scan_results(self):
        """Limpia los resultados del escaneo"""
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.devices_data = []
    
    # ========== MÉTODOS DE PUERTOS ==========
    
    def analyze_selected_ports(self):
        """Analiza puertos del dispositivo seleccionado"""
        selected = self.scan_tree.selection()
        if not selected:
            messagebox.showwarning("Advertencia", "Selecciona un dispositivo primero")
            return
        
        values = self.scan_tree.item(selected[0])["values"]
        ip = values[0]
        
        self.port_ip_entry.delete(0, tk.END)
        self.port_ip_entry.insert(0, ip)
        self.start_port_scan()
    
    def start_port_scan(self):
        """Inicia el escaneo de puertos"""
        ip = self.port_ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Advertencia", "Ingresa una dirección IP válida")
            return
        
        self.port_tree.delete(*self.port_tree.get_children())
        
        self.scan_thread = threading.Thread(target=self._port_scan_thread, args=(ip,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def _port_scan_thread(self, ip):
        """Ejecuta el escaneo de puertos en un hilo"""
        try:
            open_ports = self.port_analyzer.scan_ports_threaded(ip)
            
            for port_info in open_ports:
                self.root.after(0, lambda p=port_info: self._insert_port_row(p))
            
            self.root.after(0, lambda: messagebox.showinfo("Éxito", f"Escaneo de puertos completado. {len(open_ports)} puertos abiertos."))
        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Error en escaneo de puertos: {str(e)}"))
    
    def _insert_port_row(self, port_info):
        """Inserta una fila en la tabla de puertos"""
        values = (
            port_info.get("puerto"),
            port_info.get("servicio"),
            port_info.get("estado")
        )
        self.port_tree.insert("", tk.END, values=values)
    
    # ========== MÉTODOS DE TRÁFICO ==========
    
    def show_traffic_stats(self):
        """Muestra estadísticas de tráfico"""
        stats = self.traffic_analyzer.get_statistics()
        
        stats_text = "=" * 60 + "\n"
        stats_text += "ESTADÍSTICAS DE TRÁFICO DE RED\n"
        stats_text += "=" * 60 + "\n\n"
        
        stats_text += f"Total de paquetes capturados: {stats.get('total_paquetes', 0)}\n"
        stats_text += f"Tamaño promedio de paquete: {stats.get('tamaño_promedio', 0)} bytes\n\n"
        
        stats_text += "Protocolos Detectados:\n"
        for protocolo, cantidad in stats.get("protocolos", {}).items():
            stats_text += f"  • {protocolo}: {cantidad} paquetes\n"
        
        stats_text += "\nIPs Origen Principales:\n"
        for ip, cantidad in sorted(stats.get("ips_origen", {}).items(), key=lambda x: x[1], reverse=True)[:10]:
            stats_text += f"  • {ip}: {cantidad} paquetes\n"
        
        stats_text += "\nIPs Destino Principales:\n"
        for ip, cantidad in sorted(stats.get("ips_destino", {}).items(), key=lambda x: x[1], reverse=True)[:10]:
            stats_text += f"  • {ip}: {cantidad} paquetes\n"
        
        self.traffic_text.config(state=tk.NORMAL)
        self.traffic_text.delete(1.0, tk.END)
        self.traffic_text.insert(1.0, stats_text)
        self.traffic_text.config(state=tk.DISABLED)
    
    # ========== MÉTODOS DE VULNERABILIDADES ==========
    
    def analyze_vulnerabilities(self):
        """Analiza vulnerabilidades de dispositivos detectados"""
        if not self.devices_data:
            messagebox.showwarning("Advertencia", "Primero realiza un escaneo de red")
            return
        
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        self.vulnerabilities_data = []
        
        self.scan_thread = threading.Thread(target=self._vulnerability_analysis_thread)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def _vulnerability_analysis_thread(self):
        """Analiza vulnerabilidades en hilo separado"""
        try:
            for device in self.devices_data:
                if not self.scanner.scan_active:
                    break
                
                # Escanear puertos del dispositivo
                open_ports = self.port_analyzer.scan_ports(device["ip"], timeout=1)
                
                # Detectar vulnerabilidades
                vulns = self.vulnerability_detector.detect_vulnerabilities(device["ip"], open_ports)
                
                for vuln in vulns:
                    self.vulnerabilities_data.append(vuln)
                    self.root.after(0, lambda v=vuln: self._insert_vulnerability_row(v))
            
            total_vulns = len(self.vulnerabilities_data)
            self.root.after(0, lambda: messagebox.showinfo("Análisis Completado", f"Se detectaron {total_vulns} vulnerabilidades"))
        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Error en análisis: {str(e)}"))
    
    def _insert_vulnerability_row(self, vuln):
        """Inserta una vulnerabilidad en la tabla"""
        values = (
            vuln.get("dispositivo"),
            vuln.get("servicio"),
            vuln.get("puerto"),
            vuln.get("riesgo"),
            vuln.get("descripcion")
        )
        self.vuln_tree.insert("", tk.END, values=values)
    
    def generate_vulnerability_report(self):
        """Genera un reporte de vulnerabilidades"""
        if not self.vulnerabilities_data:
            messagebox.showwarning("Advertencia", "Primero analiza vulnerabilidades")
            return
        
        data = {
            "dispositivos": self.devices_data,
            "vulnerabilidades": self.vulnerabilities_data,
            "timestamp": datetime.now().isoformat(),
            "total_dispositivos": len(self.devices_data),
            "total_vulnerabilidades": len(self.vulnerabilities_data)
        }
        
        filepath = self.report_generator.generate_html_report(data)
        messagebox.showinfo("Éxito", f"Reporte generado en:\n{filepath}")
    
    # ========== MÉTODOS DE REPORTES ==========
    
    def generate_report(self, formato):
        """Genera un reporte en el formato especificado"""
        if not self.devices_data:
            messagebox.showwarning("Advertencia", "Primero realiza un escaneo de red")
            return
        
        try:
            if formato == "json":
                data = {
                    "dispositivos": self.devices_data,
                    "vulnerabilidades": self.vulnerabilities_data,
                    "timestamp": datetime.now().isoformat()
                }
                filepath = self.report_generator.generate_json_report(data)
            
            elif formato == "csv":
                filepath = self.report_generator.generate_csv_report(self.devices_data)
            
            elif formato == "html":
                data = {
                    "dispositivos": self.devices_data,
                    "vulnerabilidades": self.vulnerabilities_data,
                    "timestamp": datetime.now().isoformat()
                }
                filepath = self.report_generator.generate_html_report(data)
            
            messagebox.showinfo("Éxito", f"Reporte {formato.upper()} generado en:\n{filepath}")
            self.refresh_reports_list()
        
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar reporte: {str(e)}")
    
    def open_reports_folder(self):
        """Abre la carpeta de reportes"""
        try:
            if platform.system() == "Windows":
                os.startfile(self.report_generator.reports_dir)
            elif platform.system() == "Darwin":  # macOS
                subprocess.Popen(["open", self.report_generator.reports_dir])
            else:  # Linux
                subprocess.Popen(["xdg-open", self.report_generator.reports_dir])
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir la carpeta: {str(e)}")
    
    def refresh_reports_list(self):
        """Actualiza la lista de reportes generados"""
        try:
            reports = os.listdir(self.report_generator.reports_dir)
            
            self.reports_text.config(state=tk.NORMAL)
            self.reports_text.delete(1.0, tk.END)
            
            text = "REPORTES GENERADOS\n"
            text += "=" * 60 + "\n\n"
            
            if reports:
                for i, report in enumerate(sorted(reports, reverse=True), 1):
                    filepath = os.path.join(self.report_generator.reports_dir, report)
                    size = os.path.getsize(filepath)
                    mod_time = datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d %H:%M:%S")
                    
                    text += f"{i}. {report}\n"
                    text += f"   Tamaño: {size / 1024:.2f} KB\n"
                    text += f"   Modificado: {mod_time}\n\n"
            else:
                text += "No hay reportes generados aún.\n"
            
            self.reports_text.insert(1.0, text)
            self.reports_text.config(state=tk.DISABLED)
        
        except Exception as e:
            messagebox.showerror("Error", f"Error al actualizar lista: {str(e)}")
    
    # ========== MÉTODOS GENERALES ==========
    
    def export_devices_csv(self):
        """Exporta dispositivos a CSV"""
        if not self.devices_data:
            messagebox.showwarning("Advertencia", "No hay dispositivos para exportar")
            return
        
        filepath = self.report_generator.generate_csv_report(self.devices_data)
        messagebox.showinfo("Éxito", f"Dispositivos exportados a:\n{filepath}")
    
    def show_about(self):
        """Muestra diálogo de información"""
        about_text = """
RedGuardian v1.0.0
Herramienta Profesional de Análisis de Red

Desarrollado para análisis y monitoreo 
seguro de redes locales.

⚠️ USO ÉTICO Y LEGAL SOLAMENTE
Requiere autorización del administrador de red.

Características:
• Escaneo de dispositivos en red
• Análisis de puertos abiertos
• Detección de vulnerabilidades
• Generación de reportes profesionales
• Interfaz intuitiva y fácil de usar

© 2024 Red Guardian Development Team
Licencia: MIT
"""
        messagebox.showinfo("Acerca de RedGuardian", about_text)


# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main():
    """Función principal que inicia la aplicación"""
    if not SCAPY_AVAILABLE:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Dependencia faltante",
            "Scapy no está instalado.\n\n"
            "Instálalo ejecutando:\npip install scapy\n\n"
            "En algunos sistemas puede requerir sudo."
        )
        root.destroy()
        return
    
    root = tk.Tk()
    app = RedGuardianGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
