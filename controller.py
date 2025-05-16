from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from collections import defaultdict
import time

class HoneypotController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HoneypotController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.blocked_ips = set()
        self.traffic_log = defaultdict(list)

        # Honeyports and redirection rules
        self.honeypots = {
            'web': {'ip': '192.168.99.10', 'mac': '00:00:00:99:00:10'},
            'ssh': {'ip': '192.168.99.11', 'mac': '00:00:00:99:00:11'}
        }

        self.redirect_targets = {
            '192.168.30.200': 'web',  # example 1
            '192.168.30.201': 'ssh'   # example 2
        }

        # Simple port scanning detection
        self.scan_window = 10 # seconds
        self.scan_threshold = 5 # unique ports per source in window
        self.port_activity = defaultdict(lambda: defaultdict(list)) # src_ip -> dst_ip -> timestamps

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Send all unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Allow ARP packets to flood
        match_arp = parser.OFPMatch(eth_type=0x0806)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1, match_arp, actions_arp)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=instructions)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=instructions)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto    

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if not eth or eth.ethertype != 0x0800 or not ip_pkt:
            return # Ignore non-IPv4 

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        src_mac = eth.src
        dst_mac = eth.dst
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        self.mac_to_port[dpid][src_mac] = in_port

        # Block traffic from malicious IPs
        if src_ip in self.blocked_ips:
            self.logger.warning("Dropping traffic from blocked IP: %s", src_ip)
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            actions = []
            self.add_flow(datapath, 100, match, actions)
            return

        # --- Port scan detection ---
        now = time.time()
        dst = dst_ip
        self.port_activity[src_ip][dst].append(now)
        self.cleanup_old_activity(src_ip)

        unique_ports = len(self.port_activity[src_ip])
        if unique_ports >= self.scan_threshold:
            self.logger.warning("Port scan detected from %s - blocking", src_ip)
            self.blocked_ips.add(src_ip)
            match = parser.OFPMatch(eth_type=0x800, ipv4_src=src_ip)
            actions = []
            self.add_flow(datapath, 100, match, actions)
            return

        # --- Honeypot redirection ---
        if dst_ip in self.redirect_targets:
            honeypot = self.honeypots[self.redirect_targets[dst_ip]]
            self.logger.info("Redirecting traffic from %s -> %s to honeypot %s", src_ip, dst_ip, honeypot['ip'])

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
            actions = [
                parser.OFPActionSetField(ipv4_dst=honeypot['ip']),
                parser.OFPActionSetField(eth_dst=honeypot['mac']),
                parser.OFPActionOutput(ofproto.OFPP_FLOOD)
            ]
            self.add_flow(datapath, 20, match, actions)
            return

        # --- Default L2 switch behavior ---
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
        self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    def cleanup_old_activity(self, src_ip):
        now = time.time()
        for dst in list(self.port_activity[src_ip]):
            timestamps = self.port_activity[src_ip][dst]
            self.port_activity[src_ip][dst] = [t for t in timestamps if now - t <= self.scan_window]
            if not self.port_activity[src_ip][dst]:
                del self.port_activity[src_ip][dst]