# SDS_HACK_MININET

## Description

This project is a **penetration testing** tool designed to run various security tests on target machines. Currently, it supports **nmap scanning** and **SSH brute-force attack** functionalities. Additional features like **DoS attacks** (SYN flood, UDP flood) and **Telnet testing** are in progress.

## Installation

1. **Install the dependencies**:

   Run the following script to install the necessary dependencies:

   ```bash
   ./setup.sh
   ```

2.  **Configuring the Target Machine**

Allow the target ports in the target machine/s: sudo ufw allow xx/tcp 
In this case, the target IP: 192.168.1.150.
Tested with ports: 3000, 8000, and 22.

   ```bash
   sudo ufw allow 22/tcp
   ```


4.  **Execute the tool**:
   ```python
   sudo python3 script.sh
   ```

DoS SYN and UDP flood with hping3 are working
To check the received packets use:

DoS SYN: 
 ```bash
sudo netstat -antp | grep SYN_RECV
```

DoS UDP: 
```bash
sudo tcpdump -i any udp
```


