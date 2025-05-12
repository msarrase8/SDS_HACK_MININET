#!/bin/bash

echo "[*] Instalando herramientas necesarias..."

# Actualiza repositorios
sudo apt update

# Instala herramientas del sistema
sudo apt install -y nmap hping3 telnet python3-pip

# Verifica si Python ya tiene las librerías
pip3 install -r requirements.txt

echo "[✔] Entorno listo para ejecutar ataques"
