#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Instalador de dependencias para RedGuardian
"""

import subprocess
import sys

def install_dependencies():
    """Instala todas las dependencias necesarias"""
    
    dependencies = [
        "scapy",
        "psutil",
        "python-nmap"
    ]
    
    print("=" * 60)
    print("Instalando dependencias para RedGuardian...")
    print("=" * 60)
    
    for dependency in dependencies:
        print(f"\n📦 Instalando {dependency}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dependency])
            print(f"✅ {dependency} instalado correctamente")
        except subprocess.CalledProcessError as e:
            print(f"❌ Error instalando {dependency}: {e}")
    
    print("\n" + "=" * 60)
    print("✅ Instalación completada!")
    print("=" * 60)
    print("\n⚡ Para ejecutar RedGuardian:")
    print("  • Linux/macOS: sudo python3 redguardian.py")
    print("  • Windows: Ejecutar como Administrador: python redguardian.py")

if __name__ == "__main__":
    install_dependencies()
