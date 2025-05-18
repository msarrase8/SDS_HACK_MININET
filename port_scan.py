#!/usr/bin/env python3
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port, timeout=1):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"Port {port}: OPEN")
            return port
        sock.close()
        return None
    except:
        return None

def scan_range(ip, start_port, end_port, threads=10, delay=0):
    """Scan a range of ports"""
    print(f"Scanning {ip} from port {start_port} to {end_port}...")
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for port in range(start_port, end_port + 1):
            futures.append(executor.submit(scan_port, ip, port))
            if delay > 0:
                time.sleep(delay)
        
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
    
    print(f"\nScan complete! Found {len(open_ports)} open ports.")
    if open_ports:
        print("Open ports:", ", ".join(map(str, sorted(open_ports))))
    
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} TARGET_IP [START_PORT] [END_PORT] [THREADS] [DELAY]")
        print("  TARGET_IP  - The IP address to scan")
        print("  START_PORT - First port to scan (default: 1)")
        print("  END_PORT   - Last port to scan (default: 1000)")
        print("  THREADS    - Number of concurrent scans (default: 10)")
        print("  DELAY      - Delay between port scans in seconds (default: 0)")
        sys.exit(1)
    
    target = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
    threads = int(sys.argv[4]) if len(sys.argv) > 4 else 10
    delay = float(sys.argv[5]) if len(sys.argv) > 5 else 0
    
    scan_range(target, start, end, threads, delay)