from mininet.topo import Topo
# from mininet.link import TCLink

class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        # Define a virtual gateway IP for the attacker's external network
        #VGW_EXTERNAL_IP = '100.100.100.1' # sw_edge will act as this gateway for the attacker

        # Control network (192.168.10.0/24)
        idsSnort = self.addHost('idsSnort', ip='192.168.10.10/24', mac='00:00:00:10:00:10')
        logServer = self.addHost('logServer', ip='192.168.10.11/24', mac='00:00:00:10:00:11')
        # Attacker
        attacker = self.addHost('attacker', ip='192.168.10.12/24', mac='00:00:00:DE:AD:01')
                        #defaultRoute='via {}'.format(VGW_EXTERNAL_IP))

        # LAN network (192.168.20.0/24)
        pc1 = self.addHost('pc1', ip='192.168.20.10/24', mac='00:00:00:20:00:10')
        pc2 = self.addHost('pc2', ip='192.168.20.11/24', mac='00:00:00:20:00:11')
        srvDb = self.addHost('srvDb', ip='192.168.20.20/24', mac='00:00:00:20:00:20')
        srvFiles = self.addHost('srvFiles', ip='192.168.20.21/24', mac='00:00:00:20:00:21')

        # DMZ network (192.168.30.0/24)
        srvWeb = self.addHost('srvWeb', ip='192.168.30.10/24', mac='00:00:00:30:00:10')
        srvDns = self.addHost('srvDns', ip='192.168.30.11/24', mac='00:00:00:30:00:11')

        # Honeynet network (192.168.99.0/24)
        hpWindows = self.addHost('hpWindows', ip='192.168.99.12/24', mac='00:00:00:99:00:12')
        hpSsh = self.addHost('hpSsh', ip='192.168.99.11/24', mac='00:00:00:99:00:11')
        hpWeb = self.addHost('hpWeb', ip='192.168.99.10/24', mac='00:00:00:99:00:10')


        # Switches
        sw_control = self.addSwitch('s1')  # For 192.168.10.0/24
        sw_lan = self.addSwitch('s2')      # For 192.168.20.0/24
        sw_dmz = self.addSwitch('s3')      # For 192.168.30.0/24
        sw_honeynet = self.addSwitch('s4') # For 192.168.99.0/24
        sw_core = self.addSwitch('s5')     # Core switch
        sw_edge = self.addSwitch('s6')     # Edge switch

        # Links for hosts to their respective departmental switches
        self.addLink(idsSnort, sw_control)
        self.addLink(logServer, sw_control)

        self.addLink(pc1, sw_lan)
        self.addLink(pc2, sw_lan)
        self.addLink(srvDb, sw_lan)
        self.addLink(srvFiles, sw_lan)

        self.addLink(srvWeb, sw_dmz)
        self.addLink(srvDns, sw_dmz)

        self.addLink(hpWindows, sw_honeynet)
        self.addLink(hpSsh, sw_honeynet)
        self.addLink(hpWeb, sw_honeynet)

        # Links from departmental switches to the core switch
        self.addLink(sw_lan, sw_core)
        self.addLink(sw_dmz, sw_core)
        self.addLink(sw_honeynet, sw_core)

        # Links from core and control switch to the edge switch
        self.addLink(sw_core, sw_edge)
        self.addLink(sw_control, sw_edge)

        # Attacker is connected to the edge switch
        self.addLink(attacker, sw_edge)

        # Añadir router (sin IP por ahora)
        router = self.addHost('router', ip=None)

        # Enlaces desde el router a cada red
        self.addLink(router, sw_control)   # conectará con 192.168.10.0/24
        self.addLink(router, sw_lan)       # conectará con 192.168.20.0/24
        self.addLink(router, sw_dmz)       # conectará con 192.168.30.0/24
        self.addLink(router, sw_honeynet)  # conectará con 192.168.99.0/24




topos = {'mytopo': (lambda: MyTopo())}