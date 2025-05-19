#!/usr/bin/env python3
from operator import attrgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ether_types # Ensure ether_types is imported
from ryu.lib import hub

import socket
import datetime
import time # For port scan detection logic
from collections import defaultdict

# --- Configuration for Telegraf Connection ---
# Telegraf should be running on the same host as Ryu, listening on this UDP port.
# Telegraf's configuration (telegraf.conf) must have an [[inputs.socket_listener]]
# configured for this address and data_format = "influx".
TELEGRAF_UDP_IP = "127.0.0.1"
TELEGRAF_UDP_PORT = 8094
# --- End Telegraf Configuration ---

class HoneypotController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # --- InfluxDB Line Protocol Message Formats ---
    # Measurement name for flow statistics
    # Tags: datapath_id (switch ID), in_port (hex), eth_dst (MAC string)
    # Fields: out_port (hex string), packets (integer), bytes (integer)
    FLOW_STATS_MSG_FORMAT = "sds_flow_stats,datapath_id={dp_id},in_port={in_port},eth_dst=\"{eth_dst}\" " \
                            "out_port=\"{out_port}\",packets={packets}i,bytes={bytes}i {timestamp}"

    # Measurement name for port statistics
    # Tags: datapath_id (switch ID), port_no (hex)
    # Fields: rx_pkts, rx_bytes, rx_errors, tx_pkts, tx_bytes, tx_errors (all integers)
    PORT_STATS_MSG_FORMAT = "sds_port_stats,datapath_id={dp_id},port_no={port_no} " \
                            "rx_packets={rx_pkts}i,rx_bytes={rx_bytes}i,rx_errors={rx_err}i," \
                            "tx_packets={tx_pkts}i,tx_bytes={tx_bytes}i,tx_errors={tx_err}i {timestamp}"
    # --- End InfluxDB Format Strings ---

    def __init__(self, *args, **kwargs):
        super(HoneypotController, self).__init__(*args, **kwargs)
        
        # Core L2 switching state
        self.mac_to_port = {}  # {dpid: {mac_addr: out_port}}

        # --- Placeholders for Security Logic (from your original controller) ---
        self.blocked_ips = set()
        # self.traffic_log = defaultdict(list) # Example: Not currently used, can be removed if not planned
        
        # Example Honeypot definitions (adjust IPs/MACs based on your MyTopo.py)
        self.honeypots = {
            'web': {'ip': '192.168.99.10', 'mac': '00:00:00:99:00:10'}, # hpWeb
            'ssh': {'ip': '192.168.99.11', 'mac': '00:00:00:99:00:11'}  # hpSsh
        }
        # Example target IPs that, if scanned/attacked, trigger redirection
        # These IPs might be "virtual" or actual IPs of your servers like srvWeb.
        self.redirect_targets = {
            # '192.168.30.10': 'web',  # Example: If srvWeb is targeted, redirect to 'web' honeypot
            # 'some_other_ip_to_protect': 'ssh'
        }
        
        # Example Port Scanning Detection (can be refined or expanded)
        self.scan_window = 10 # seconds (time window to count scanned ports)
        self.scan_threshold = 5 # unique destination ports from a source to trigger alert/block
        # Structure: {src_ip: { (dst_ip, dst_port) : [timestamp1, timestamp2] }}
        self.port_activity = defaultdict(lambda: defaultdict(list))
        # --- End Security Logic Placeholders ---

        # --- Traffic Monitoring Setup ---
        self.datapaths = {}  # {dpid: datapath_object}
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("HoneypotController initialized: L2 switching, monitoring thread started. Security logic placeholders active.")

    # --- OpenFlow Switch Connection Management (for L2 learning and Monitoring) ---
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        dpid = datapath.id
        if ev.state == MAIN_DISPATCHER:
            if dpid not in self.datapaths:
                self.logger.info(f'Registering datapath: {dpid:016x}')
                self.datapaths[dpid] = datapath
                self.mac_to_port.setdefault(dpid, {}) # Initialize mac_to_port for new switch
        elif ev.state == DEAD_DISPATCHER:
            if dpid in self.datapaths:
                self.logger.info(f'Unregistering datapath: {dpid:016x}')
                del self.datapaths[dpid]
                if dpid in self.mac_to_port:
                    del self.mac_to_port[dpid]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.mac_to_port.setdefault(dpid, {}) # Also ensure it's here for initial connection
        self.logger.info(f"Switch {dpid:016x} connected (features_handler).")

        # Install table-miss flow entry (send to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions) # Priority 0
        self.logger.info(f"Installed table-miss flow for switch {dpid:016x}")

        # Install rule to flood ARP packets
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1, match_arp, actions_arp) # Priority 1 for ARP
        self.logger.info(f"Installed ARP flooding rule for switch {dpid:016x}")
    # --- End OpenFlow Switch Connection Management ---

    # --- Flow Mod Utility ---
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod_args = {
            'datapath': datapath, 'priority': priority, 'match': match,
            'instructions': instructions, 'idle_timeout': idle_timeout, 'hard_timeout': hard_timeout
        }
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod_args['buffer_id'] = buffer_id
        mod = parser.OFPFlowMod(**mod_args)
        datapath.send_msg(mod)
    # --- End Flow Mod Utility ---

    # --- Traffic Monitoring Core Logic ---
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(10) # Stats request interval

    def _request_stats(self, datapath):
        self.logger.debug(f'Sending stats request to datapath: {datapath.id:016x}')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Request Flow Statistics
        match_all_flows = parser.OFPMatch()
        req_flow = parser.OFPFlowStatsRequest(datapath, 0, ofproto.OFPTT_ALL,
                                           ofproto.OFPP_ANY, ofproto.OFPG_ANY,
                                           0, 0, match_all_flows)
        datapath.send_msg(req_flow)

        # Request Port Statistics
        req_port = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req_port)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dp_id_str = f"{ev.msg.datapath.id:016x}"
        self.logger.info(f"Received flow stats from DPID: {dp_id_str} (Raw count: {len(body)})")
        
        active_flows = [flow for flow in body if flow.priority >= 1]
        if not active_flows:
            self.logger.debug(f"No active flows (priority >=1) to report for DPID: {dp_id_str}")
            return
        # self.logger.info(f"Processing {len(active_flows)} flows with priority >= 1 from DPID: {dp_id_str}")

        for stat in sorted(active_flows, key=lambda flow: (str(flow.match.get('in_port','')), str(flow.match.get('eth_dst','')))):
            self.logger.debug(f"--- Flow Stat Detail (DPID: {dp_id_str}, Prio: {stat.priority}) ---\n"
                             f"Match: {stat.match}\nInstructions: {stat.instructions}\n"
                             f"PktCount: {stat.packet_count}, ByteCount: {stat.byte_count}")

            in_port_val = stat.match.get('in_port')
            in_port_tag_val = (f"{int(in_port_val):x}" if isinstance(in_port_val, int) else str(in_port_val)) if in_port_val is not None else "unknown_in_port"
            eth_dst_tag_val = str(stat.match.get('eth_dst', "unknown_eth_dst"))
            out_port_field_val = "N/A"
            if stat.instructions:
                for instruction in stat.instructions:
                    if hasattr(instruction, 'actions'):
                        for action in instruction.actions:
                            if hasattr(action, 'port'):
                                out_port_field_val = (f"{action.port:x}" if isinstance(action.port, int) else str(action.port))
                                break
                        if out_port_field_val != "N/A": break
            
            timestamp_ns = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1e9)
            try:
                msg_line = HoneypotController.FLOW_STATS_MSG_FORMAT.format(
                    dp_id=dp_id_str, in_port=in_port_tag_val, eth_dst=eth_dst_tag_val,
                    out_port=out_port_field_val, packets=stat.packet_count, bytes=stat.byte_count,
                    timestamp=timestamp_ns)
                self.logger.info(f"FlowStat Line: {msg_line}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(msg_line.encode('utf-8'), (TELEGRAF_UDP_IP, TELEGRAF_UDP_PORT))
            except Exception as e:
                self.logger.error(f"Error sending flow stat: {e} for msg: '{locals().get('msg_line', 'FORMAT_ERROR')}'")

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dp_id_str = f"{ev.msg.datapath.id:016x}"
        self.logger.info(f"Received port stats from DPID: {dp_id_str} (Count: {len(body)})")

        for stat in sorted(body, key=attrgetter('port_no')):
            if stat.port_no > ev.msg.datapath.ofproto.OFPP_MAX: continue
            timestamp_ns = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1e9)
            port_no_hex = f"{stat.port_no:x}"
            try:
                msg_line = HoneypotController.PORT_STATS_MSG_FORMAT.format(
                    dp_id=dp_id_str, port_no=port_no_hex,
                    rx_pkts=stat.rx_packets, rx_bytes=stat.rx_bytes, rx_err=stat.rx_errors,
                    tx_pkts=stat.tx_packets, tx_bytes=stat.tx_bytes, tx_err=stat.tx_errors,
                    timestamp=timestamp_ns)
                self.logger.info(f"PortStat Line: {msg_line}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(msg_line.encode('utf-8'), (TELEGRAF_UDP_IP, TELEGRAF_UDP_PORT))
            except Exception as e:
                self.logger.error(f"Error sending port stat: {e} for msg: '{locals().get('msg_line', 'FORMAT_ERROR')}'")
    # --- End Traffic Monitoring Core Logic ---

    # --- Main Packet-In Handler (L2 Switching + Security Logic Hooks) ---
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if not eth_pkt or eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        # Learn source MAC and port
        if self.mac_to_port[dpid].get(src_mac) != in_port: # Update if MAC moved or first time seen on this port
            self.mac_to_port[dpid][src_mac] = in_port
            self.logger.debug(f"Learned/Updated MAC {src_mac} on switch {dpid:016x} port {in_port}")

        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            # --- Placeholder: Port Scan Detection / Blocking ---
            if src_ip in self.blocked_ips:
                self.logger.warning(f"Traffic from blocked IP {src_ip} DROPPED.")
                # Optionally install a drop flow if not already done by the detection logic
                return # Drop the packet by not forwarding

            # Add your team's port scan detection logic here.
            # If a scan is detected from src_ip:
            #   self.blocked_ips.add(src_ip)
            #   self.logger.warning(f"Port scan detected from {src_ip} - BLOCKING.")
            #   match_block = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
            #   self.add_flow(datapath, 100, match_block, [], idle_timeout=300, hard_timeout=600) # Empty actions = drop
            #   return # Packet handled (dropped)

            # --- Placeholder: Honeypot Redirection (based on dst_ip) ---
            # if dst_ip in self.redirect_targets:
            #    honeypot_key = self.redirect_targets[dst_ip]
            #    honeypot_info = self.honeypots.get(honeypot_key)
            #    if honeypot_info:
            #        self.logger.info(f"Redirecting {src_ip}->{dst_ip} to honeypot {honeypot_info['ip']}")
            #        # Determine out_port_to_honeypot on THIS datapath (dpid)
            #        # This is complex: requires knowing path from current switch to honeypot.
            #        # For now, this is a placeholder.
            #        # match_redirect = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
            #        # actions_redirect = [
            #        #    parser.OFPActionSetField(eth_dst=honeypot_info['mac']),
            #        #    parser.OFPActionSetField(ipv4_dst=honeypot_info['ip']),
            #        #    parser.OFPActionOutput(out_port_to_honeypot) # Needs to be defined
            #        # ]
            #        # self.add_flow(datapath, 20, match_redirect, actions_redirect, idle_timeout=60)
            #        # Send current packet if not buffered:
            #        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            #        #    out = parser.OFPPacketOut(...)
            #        #    datapath.send_msg(out)
            #        return # Packet handled (redirected)

        # --- Default L2 Switching ---
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Install L2 flow if destination is known and it's not ARP (ARP is already flooded)
        if out_port != ofproto.OFPP_FLOOD and eth_pkt.ethertype != ether_types.ETH_TYPE_ARP:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            # Use msg.buffer_id if available to prevent re-sending the packet that triggered this flow install
            buffer_id_for_l2_flow = msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER else None
            self.add_flow(datapath, 1, match, actions, buffer_id=buffer_id_for_l2_flow, idle_timeout=60, hard_timeout=180)
            
            # If we used a valid buffer_id when adding the flow, the switch processes the packet.
            # If not (buffer_id was OFP_NO_BUFFER), we must send it via PacketOut.
            # For simplicity, simple_switch often sends PacketOut regardless if data exists.
            # If buffer_id_for_l2_flow was valid and used by add_flow (meaning the packet is buffered at switch),
            # we might not need the PacketOut below for this specific packet.
            # However, to ensure the packet always goes out (especially if add_flow didn't use buffer_id):
            if msg.buffer_id == ofproto.OFP_NO_BUFFER: # If packet data is with controller
                data = msg.data
                out_pkt = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out_pkt)
            return # Flow installed, packet processed or sent.

        # If flooding, send the packet out via PacketOut
        if out_port == ofproto.OFPP_FLOOD:
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out_pkt = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out_pkt)

    # def cleanup_old_activity(self, src_ip): # Implement if using port scan detection
    #     now = time.time()
    #     for dst_target in list(self.port_activity[src_ip]):
    #         timestamps = self.port_activity[src_ip][dst_target]
    #         self.port_activity[src_ip][dst_target] = [t for t in timestamps if (now - t) <= self.scan_window]
    #         if not self.port_activity[src_ip][dst_target]:
    #             del self.port_activity[src_ip][dst_target]
    #     if not self.port_activity[src_ip]:
    #         del self.port_activity[src_ip]