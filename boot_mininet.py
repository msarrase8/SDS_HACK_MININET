#!/usr/bin/env python3
import os
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.nodelib import NAT

from mininet.cli import CLI
from mininet.link import TCLink
from topology import MyTopo # Assuming your MyTopo class is in topology.py

# IP address for the NAT node's internal interface (gateway for Mininet's router)
NAT_INTERNAL_GW_IP = '10.0.0.1'
# The subnet where router's Mininet-facing IP (192.168.10.1) resides.
# nat0 needs a route to this network via nat0-eth0.
ROUTER_CONTROL_NET = '192.168.10.0/24' # Network of router-eth0

def setup_routing(net):
    router = net.get('router')
    print(f"Configuring interfaces and IP forwarding for host '{router.name}'...")
    router.cmd("sysctl -w net.ipv4.ip_forward=1")

    # Assign IPs to router's interfaces
    router.cmd("ifconfig router-eth0 192.168.10.1/24 up") # Connects to sw_control (s1)
    router.cmd("ifconfig router-eth1 192.168.20.1/24 up") # Connects to sw_lan (s2)
    router.cmd("ifconfig router-eth2 192.168.30.1/24 up") # Connects to sw_dmz (s3)
    router.cmd("ifconfig router-eth3 192.168.99.1/24 up") # Connects to sw_honeynet (s4)

    print(f"Disabling rp_filter on '{router.name}' interfaces...")
    router.cmd("for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done")

    # Set default routes for hosts pointing to the Mininet router
    print("Setting default gateway for Mininet hosts...")
    net.get('idsSnort').cmd("ip route add default via 192.168.10.1")
    net.get('logServer').cmd("ip route add default via 192.168.10.1")
    net.get('attacker').cmd("ip route add default via 192.168.10.1")

    for h_name in ['pc1', 'pc2', 'srvDb', 'srvFiles']:
        net.get(h_name).cmd("ip route add default via 192.168.20.1")

    for h_name in ['srvWeb', 'srvDns']:
        net.get(h_name).cmd("ip route add default via 192.168.30.1")

    for h_name in ['hpWeb', 'hpSsh', 'hpWindows']:
        net.get(h_name).cmd("ip route add default via 192.168.99.1")

    # Set default route for the 'router' itself via NAT
    print(f"Setting default route for Mininet router '{router.name}' via {NAT_INTERNAL_GW_IP} dev router-eth0 onlink")
    route_cmd_output = router.cmd(f"ip route add default via {NAT_INTERNAL_GW_IP} dev router-eth0 onlink")
    if route_cmd_output.strip():
        print(f"Output/Error from adding default route to router '{router.name}': '{route_cmd_output.strip()}'")
    else:
        print(f"Default route command for router '{router.name}' seems to have succeeded (no error output).")

    print(f"\nRoutes on Mininet router '{router.name}':")
    print(router.cmd("ip route"))

def configure_dns(net):
    print("\nConfiguring DNS for Mininet hosts (using 8.8.8.8 and 1.1.1.1)...")
    for host in net.hosts:
        if isinstance(host, NAT): # Check if the host is the NAT node
            print(f"Skipping DNS configuration for NAT node: {host.name}")
            continue
        # Ensure host name is not None and it's a Mininet host we want to configure
        if hasattr(host, 'name') and host.name in net.nameToNode:
             print(f"Setting DNS for {host.name}")
             host.cmd("echo 'nameserver 8.8.8.8' > /etc/resolv.conf")
             host.cmd("echo 'nameserver 1.1.1.1' >> /etc/resolv.conf")

if __name__ == '__main__':
    print("Ensuring host IP forwarding is enabled...")
    if os.system("sudo sysctl -w net.ipv4.ip_forward=1") != 0:
        print("Warning: Failed to enable IP forwarding on host. Internet might not work.")

    topo = MyTopo()
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  controller=RemoteController, # Or just Controller if local
                  autoSetMacs=True,
                  autoStaticArp=True
                  )

    print(f"\nAdding NAT node 'nat0' and connecting it to switch 's6' (sw_edge)...")
    nat_node = net.addNAT(name='nat0', connectToSwitch='s6')

    print("\nStarting network...")
    net.start()

    # --- Configure nat0 node ---
    print(f"\n--- Configuring nat0 ({nat_node.name}) ---")
    nat_node_internal_if = "nat0-eth0" # Interface connected to Mininet (s6)
    
    # Dynamically find nat0's external interface (the one with the default route to the internet)
    # This is more robust than hardcoding "enp0s3"
    nat_node_external_if_cmd = "ip route | grep default | awk '{print $5}'"
    nat_node_external_if = nat_node.cmd(nat_node_external_if_cmd).strip()
    if not nat_node_external_if:
        print(f"CRITICAL: Could not determine external interface for nat0. Defaulting to 'enp0s3'. Check 'ip route' on nat0.")
        nat_node_external_if = "enp0s3" # Fallback, adjust if necessary
    print(f"Determined nat0 external interface: {nat_node_external_if}")

    # 1. Configure IP on nat0's internal interface
    print(f"Manually configuring IP {NAT_INTERNAL_GW_IP}/24 on {nat_node_internal_if}...")
    nat_node.cmd(f"ifconfig {nat_node_internal_if} {NAT_INTERNAL_GW_IP}/24 up")
    print(f"IP {NAT_INTERNAL_GW_IP}/24 configured on {nat_node_internal_if}.")

    # 2. Disable rp_filter
    print(f"Disabling rp_filter on nat0...")
    nat_node.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
    nat_node.cmd(f"sysctl -w net.ipv4.conf.{nat_node_internal_if}.rp_filter=0")
    if nat_node_external_if: # Also for the external interface if found
         nat_node.cmd(f"sysctl -w net.ipv4.conf.{nat_node_external_if}.rp_filter=0")


    # 3. Add route on nat0 for router's subnet via nat0-eth0
    route_add_cmd_nat0 = f"ip route add {ROUTER_CONTROL_NET} dev {nat_node_internal_if}"
    print(f"Adding route on nat0 for {ROUTER_CONTROL_NET} via {nat_node_internal_if}: {route_add_cmd_nat0}")
    cmd_output_route_nat0 = nat_node.cmd(route_add_cmd_nat0)
    if cmd_output_route_nat0.strip() and "File exists" not in cmd_output_route_nat0:
        print(f"Output/Error adding route on nat0 for {ROUTER_CONTROL_NET}: '{cmd_output_route_nat0.strip()}'")
    else:
        print(f"Route for {ROUTER_CONTROL_NET} on nat0 configured/exists.")

    # 4. Configure iptables for NAT and Forwarding on nat0
    print(f"Configuring iptables for NAT and Forwarding on nat0...")

    # Allow forwarding of established and related connections (important for replies)
    forward_cmd1 = f"iptables -A FORWARD -i {nat_node_external_if} -o {nat_node_internal_if} -m state --state RELATED,ESTABLISHED -j ACCEPT"
    print(f"Adding: {forward_cmd1}")
    nat_node.cmd(forward_cmd1)

    # Allow forwarding of new connections from internal to external
    # The source IP will be from your Mininet hosts (e.g. 192.168.10.1)
    forward_cmd2 = f"iptables -A FORWARD -i {nat_node_internal_if} -o {nat_node_external_if} -j ACCEPT"
    print(f"Adding: {forward_cmd2}")
    nat_node.cmd(forward_cmd2)

    # NAT table: POSTROUTING chain for Masquerade
    # This changes the source IP from internal Mininet IPs to nat0's external IP
    # The source can be broad (0.0.0.0/0) if the FORWARD rules correctly restrict what comes from int_if.
    # Or, specify the source network seen on int_if, which is 10.0.0.0/24,
    # but the actual source IPs like 192.168.10.1 need to be NATed.
    # So, matching on input interface for MASQUERADE is usually fine.
    nat_masquerade_cmd = f"iptables -t nat -A POSTROUTING -o {nat_node_external_if} -j MASQUERADE"
    print(f"Adding: {nat_masquerade_cmd}")
    nat_node.cmd(nat_masquerade_cmd)
    
    # Also, ensure INPUT policy is ACCEPT or add specific rules for pinging nat0
    nat_node.cmd("iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT") # Already in screenshot
    nat_node.cmd(f"iptables -A INPUT -i {nat_node_internal_if} -p icmp --icmp-type echo-request -j ACCEPT") # Already in screenshot
    print("--- End nat0 configuration ---\n")

    # Setup routing for the Mininet 'router' and other hosts
    print("Setting up routing tables for internal Mininet hosts and router...")
    setup_routing(net)

    # Configure DNS for Mininet hosts
    configure_dns(net)

    CLI(net)

    print("\nStopping network...")
    net.stop()