#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from topology import MyTopo  # Asegúrate de que el nombre del archivo coincide

def setup_routing(net):
    router = net.get('router')
    router.cmd("sysctl -w net.ipv4.ip_forward=1")

    # Asignar IPs al router (orden de enlaces)
    router.cmd("ifconfig router-eth0 192.168.10.1/24 up")
    router.cmd("ifconfig router-eth1 192.168.20.1/24 up")
    router.cmd("ifconfig router-eth2 192.168.30.1/24 up")
    router.cmd("ifconfig router-eth3 192.168.99.1/24 up")


    # Desactivar rp_filter en todas las interfaces para permitir respuestas ICMP
    router.cmd("for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done")


    # Red de control
    net.get('idsSnort').cmd("ip route add default via 192.168.10.1")
    net.get('logServer').cmd("ip route add default via 192.168.10.1")
    net.get('attacker').cmd("ip route add default via 192.168.10.1")

    # LAN
    for h in ['pc1', 'pc2', 'srvDb', 'srvFiles']:
        net.get(h).cmd("ip route add default via 192.168.20.1")

    # DMZ
    for h in ['srvWeb', 'srvDns']:
        net.get(h).cmd("ip route add default via 192.168.30.1")

    # Honeynet
    for h in ['hpWeb', 'hpSsh', 'hpWindows']:
        net.get(h).cmd("ip route add default via 192.168.99.1")

    # Habilitar ARP proxy para respuestas en interfaces múltiples
    #router.cmd("for i in /proc/sys/net/ipv4/conf/*/arp_filter; do echo 0 > $i; done")


def safe_pingall(net):
    print("*** Safe PingAll: testing host-to-host reachability")
    for src in net.hosts:
        for dst in net.hosts:
            if src != dst:
                result = src.cmd(f'ping -c1 -W1 {dst.IP()}')
                success = '1 received' in result or '1 packets received' in result
                print(f'{src.name} -> {dst.name}: {"✔" if success else "✘"}')




if __name__ == '__main__':
    topo = MyTopo()
    net = Mininet(topo=topo, controller=RemoteController)
    net.start()
    setup_routing(net)
    #safe_pingall(net) #Check connectivity
    CLI(net)
    net.stop()
