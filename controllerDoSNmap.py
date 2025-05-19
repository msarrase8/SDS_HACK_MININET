from __future__ import print_function
import array

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from ryu.lib import snortlib


class SimpleSwitchSnort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = 4
        self.honeypot_port = 4
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.datapath = None
        self.honeypot_ip = '192.168.99.12'

        socket_config = {'unixsock': True}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))
        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)
        if _ipv4:
            self.logger.info("%r", _ipv4)
        if eth:
            self.logger.info("%r", eth)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        alert_text = msg.alertmsg[0].decode()

        print('alertmsg: %s' % alert_text)
        self.packet_print(msg.pkt)

        pkt = packet.Packet(array.array('B', msg.pkt))
        ip = pkt.get_protocol(ipv4.ipv4)

        if not ip or not self.datapath:
            return

        src_ip = ip.src
        dst_ip = ip.dst

        if "NMAP SYN scan to port 80" in alert_text:
            self.logger.info(f"[!] Escaneo NMAP detectado de {src_ip}, redirigiendo TODO su tráfico al honeypot.")
            self.add_redirect_flow(self.datapath, src_ip)
            self.add_reverse_flow(self.datapath, src_ip, dst_ip)

        elif "Possible DoS Attack Type : SYN flood" in alert_text:
            self.logger.warning(f"[!] SYN Flood detectado de {src_ip}, BLOQUEANDO tráfico completamente.")
            self.block_ip(self.datapath, src_ip)

        else:
            self.logger.info("Alerta detectada, pero no es NMAP ni SYN flood.")

    def add_redirect_flow(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = [
            parser.OFPActionSetField(ipv4_dst=self.honeypot_ip),
            parser.OFPActionOutput(self.honeypot_port)
        ]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst)
        datapath.send_msg(mod)

        self.logger.info(f"[+] Todo el tráfico de {src_ip} será redirigido al honeypot ({self.honeypot_ip})")

    def add_reverse_flow(self, datapath, attacker_ip, original_target_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        victim_mac = self.ip_to_mac.get(original_target_ip)
        if not victim_mac:
            self.logger.warning(f"[!] No se encontró la MAC para {original_target_ip}. Usando MAC por defecto.")
            victim_mac = "00:00:00:99:00:12"

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=self.honeypot_ip,
            ipv4_dst=attacker_ip
        )

        out_port = self.mac_to_port.get(datapath.id, {}).get(attacker_ip, ofproto.OFPP_FLOOD)

        actions = [
            parser.OFPActionSetField(ipv4_src=original_target_ip),
            parser.OFPActionSetField(eth_src=victim_mac),
            parser.OFPActionOutput(out_port)
        ]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=101, match=match, instructions=inst)
        datapath.send_msg(mod)

        self.logger.info(f"[+] Reverse flow añadido: honeypot → atacante, con identidad de {original_target_ip} ({victim_mac})")

    def block_ip(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            ipv4_src=src_ip
        )

        instructions = []

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=0,
            priority=500,
            match=match,
            instructions=instructions,
            idle_timeout=0,
            hard_timeout=0,
            cookie=0x1
        )
        datapath.send_msg(flow_mod)
        self.logger.info(f"[+] DROP aplicado: tráfico de {src_ip} bloqueado.")

    def allow_arp(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=10,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.allow_arp(datapath)

    def add_flow(self, datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if ipv4_pkt:
            self.ip_to_mac[ipv4_pkt.src] = eth.src

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != self.snort_port:
            actions.append(parser.OFPActionOutput(self.snort_port))

        if out_port != ofproto.OFPP_FLOOD and eth.ethertype != 0x0806:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
