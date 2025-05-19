#!/usr/bin/env python3
from operator import attrgetter
import array

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp, tcp, udp, ether_types # Added icmp, tcp, udp
from ryu.lib import hub
from ryu.lib import snortlib

import socket
import datetime
import time
from collections import defaultdict

# --- Configuration for Telegraf Connection ---
TELEGRAF_UDP_IP = "127.0.0.1"
TELEGRAF_UDP_PORT = 8094
# --- End Telegraf Configuration ---

class HoneypotController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    FLOW_STATS_MSG_FORMAT = "sds_flow_stats,datapath_id={dp_id},in_port={in_port},eth_dst=\"{eth_dst}\" " \
                            "out_port=\"{out_port}\",packets={packets}i,bytes={bytes}i {timestamp}"
    PORT_STATS_MSG_FORMAT = "sds_port_stats,datapath_id={dp_id},port_no={port_no} " \
                            "rx_packets={rx_pkts}i,rx_bytes={rx_bytes}i,rx_errors={rx_err}i," \
                            "tx_packets={tx_pkts}i,tx_bytes={tx_bytes}i,tx_errors={tx_err}i {timestamp}"

    def __init__(self, *args, **kwargs):
        super(HoneypotController, self).__init__(*args, **kwargs)
        
        self.mac_to_port = {}
        self.ip_to_mac_map = {} 
        self.flagged_attackers_for_honeypot = set()
        self.blocked_ips_by_controller = set()

        # --- Snortlib setup ---
        self.snort = kwargs['snortlib']
        self.snort_socket_path = '/tmp/snort_alert.sock' # Socket Snort on host uses
        socket_config = {'unixsock': True, 'unixsock_path': self.snort_socket_path}
        try:
            self.snort.set_config(socket_config)
            self.snort.start_socket_server()
            self.logger.info(f"SnortLib socket server configured for: {self.snort_socket_path}")
        except Exception as e:
            self.logger.error(f"Error starting SnortLib socket server on {self.snort_socket_path}: {e}")

        # --- CONFIGURATION REQUIRED BY USER ---
        # DPID of the switch where attacker traffic is first seen and where redirection/blocking rules will be installed.
        # Typically your edge switch (e.g., s6 if attacker is connected to s6).
        self.mirror_switch_dpid = 6 # EXAMPLE: sw_edge (s6). Verify from 'dpctl show' or Mininet links.

        # OpenFlow port on 'mirror_switch_dpid' used to send mirrored traffic TO THE HOST SNORT.
        # This port number will be used in 'ovs-vsctl add-port <mirror_switch> <host_dummy_if> -- set interface <host_dummy_if> ofport_request=X'.
        self.mirror_to_host_snort_port = 4 # EXAMPLE: Ensure this port is unused on the mirror_switch_dpid.

        # Honeypot details (from your MyTopo.py)
        self.honeypot_ip = '192.168.99.12'    # hpWindows IP
        self.honeypot_mac = '00:00:00:99:00:12' # hpWindows MAC

        # Port on 'mirror_switch_dpid' that is the NEXT HOP towards the honeypot.
        # Example Path: attacker -> s6 (mirror_switch) -> s5 (sw_core) -> s4 (sw_honeynet) -> hpWindows (on s4)
        # In this case, this is the port on s6 that connects to s5.
        self.output_port_on_mirror_switch_to_honeypot_path = 1 # EXAMPLE: s6-eth1 connects s6 to s5. VERIFY THIS PORT NUMBER.
        # --- END CONFIGURATION REQUIRED BY USER ---

        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        
        self.logger.info("HoneypotController initialized.")
        self._log_initial_config()

    def _log_initial_config(self):
        self.logger.info("--- Controller Configuration Check ---")
        self.logger.info(f"SnortLib Socket Path: {self.snort_socket_path}")
        self.logger.info(f"Mirroring FROM Switch DPID: {self.mirror_switch_dpid}")
        self.logger.info(f"Mirroring TO Host Snort via OFPort: {self.mirror_to_host_snort_port}")
        self.logger.info(f"Honeypot IP: {self.honeypot_ip}, MAC: {self.honeypot_mac}")
        self.logger.info(f"Redirection Output Port (on mirror switch towards honeypot path): {self.output_port_on_mirror_switch_to_honeypot_path}")
        if None in [self.mirror_switch_dpid, self.mirror_to_host_snort_port, self.output_port_on_mirror_switch_to_honeypot_path]:
            self.logger.critical("CRITICAL CONFIGURATION MISSING: DPIDs or Ports for mirroring/honeypot are None. Functionality will be impaired.")
        self.logger.info("------------------------------------")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        dpid = datapath.id
        if ev.state == MAIN_DISPATCHER:
            if dpid not in self.datapaths:
                self.logger.info(f'Registering datapath: {dpid:016x}')
                self.datapaths[dpid] = datapath
                self.mac_to_port.setdefault(dpid, {})
        elif ev.state == DEAD_DISPATCHER:
            if dpid in self.datapaths:
                self.logger.info(f'Unregistering datapath: {dpid:016x}')
                del self.datapaths[dpid]
                if dpid in self.mac_to_port: del self.mac_to_port[dpid]
                # Consider clearing ip_to_mac_map entries related to this dpid if it's per-DPID.
                # If ip_to_mac_map is global, this might not be necessary or straightforward.

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info(f"Switch {dpid:016x} connected (features_handler).")
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1, match_arp, actions_arp)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0, cookie=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod_args = {
            'datapath': datapath, 'priority': priority, 'match': match, 'cookie': cookie,
            'instructions': instructions, 'idle_timeout': idle_timeout, 'hard_timeout': hard_timeout
        }
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod_args['buffer_id'] = buffer_id
        mod = parser.OFPFlowMod(**mod_args)
        datapath.send_msg(mod)

    def _packet_print_for_alert(self, pkt_data):
        if not pkt_data: return
        try:
            pkt = packet.Packet(array.array('B', pkt_data))
            eth = pkt.get_protocol(ethernet.ethernet)
            _ipv4 = pkt.get_protocol(ipv4.ipv4)
            _icmp = pkt.get_protocol(icmp.icmp)
            self.logger.info("--- SNORT ALERT TRIGGERING PACKET ---")
            if eth: self.logger.info("%r", eth)
            if _ipv4: self.logger.info("%r", _ipv4)
            if _icmp: self.logger.info("%r", _icmp)
            self.logger.info("------------------------------------")
        except Exception as e:
            self.logger.error(f"Error in _packet_print_for_alert: {e}")

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _snort_alert_handler(self, ev):
        msg = ev.msg
        try:
            alert_text = msg.alertmsg[0].decode('utf-8')
        except Exception as e:
            self.logger.error(f"Error decoding Snort alert message: {e}, raw: {msg.alertmsg}")
            return
        self.logger.info(f'<<< Snort Alert from Host Snort: {alert_text} >>>')

        pkt_for_alert = packet.Packet(array.array('B', msg.pkt))
        ip_alert = pkt_for_alert.get_protocol(ipv4.ipv4)
        if not ip_alert:
            self.logger.warning("Alert packet missing IP header. Cannot process for redirection/blocking.")
            return

        attacker_ip = ip_alert.src
        original_dst_ip = ip_alert.dst
        datapath_to_act_on = self.datapaths.get(self.mirror_switch_dpid)
        if not datapath_to_act_on:
            self.logger.error(f"Mirror switch DPID {self.mirror_switch_dpid} not found. Cannot act on Snort alert.")
            return

        if "NMAP SYN scan to port 80" in alert_text:
            if attacker_ip not in self.flagged_attackers_for_honeypot:
                self.logger.info(f"[!] NMAP scan from {attacker_ip} to {original_dst_ip} (port 80) detected. Redirecting attacker to honeypot {self.honeypot_ip}.")
                if self.output_port_on_mirror_switch_to_honeypot_path is None:
                     self.logger.error(f"Cannot redirect {attacker_ip}: output_port_on_mirror_switch_to_honeypot_path is NOT SET.")
                     return
                self._add_redirect_and_reverse_flows(datapath_to_act_on, attacker_ip, original_dst_ip, self.output_port_on_mirror_switch_to_honeypot_path)
                self.flagged_attackers_for_honeypot.add(attacker_ip)
            else:
                self.logger.info(f"Attacker {attacker_ip} already redirected for NMAP scan.")
        elif "Possible DoS Attack Type : SYN flood" in alert_text:
            if attacker_ip not in self.blocked_ips_by_controller:
                self.logger.warning(f"[!] SYN Flood detected from {attacker_ip}. Applying block.")
                self._block_ip(datapath_to_act_on, attacker_ip)
                self.blocked_ips_by_controller.add(attacker_ip)
            else:
                self.logger.info(f"Attacker {attacker_ip} already blocked for SYN flood.")
        else:
            self.logger.info(f"Snort alert '{alert_text}' received, no specific honeypot/block action configured.")

    def _add_redirect_and_reverse_flows(self, datapath, attacker_ip, original_target_ip, out_port_to_hp_path):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.logger.info(f"Installing REDIRECT flow on DPID {datapath.id:016x}: All from {attacker_ip} -> {self.honeypot_ip} (MAC {self.honeypot_mac}) via port {out_port_to_hp_path}")
        match_redirect = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=attacker_ip)
        actions_redirect = [
            parser.OFPActionSetField(eth_dst=self.honeypot_mac),
            parser.OFPActionSetField(ipv4_dst=self.honeypot_ip),
            parser.OFPActionOutput(out_port_to_hp_path)
        ]
        self.add_flow(datapath, 100, match_redirect, actions_redirect, idle_timeout=300, hard_timeout=600, cookie=0x2A)

        original_target_mac = self.ip_to_mac_map.get(original_target_ip)
        attacker_mac = self.ip_to_mac_map.get(attacker_ip) # MAC of the attacker
        port_to_attacker = self.mac_to_port.get(datapath.id, {}).get(attacker_mac) # Port where attacker is on this datapath

        if not original_target_mac:
            self.logger.warning(f"[REVERSE] MAC for original target {original_target_ip} unknown. Using honeypot's MAC {self.honeypot_mac} as spoofed eth_src.")
            original_target_mac = self.honeypot_mac
        if not attacker_mac:
            self.logger.error(f"[REVERSE] MAC for attacker {attacker_ip} unknown. Cannot effectively install reverse flow.")
            return
        if not port_to_attacker:
            self.logger.error(f"[REVERSE] Output port to attacker {attacker_ip} (MAC {attacker_mac}) on DPID {datapath.id:016x} not found.")
            return

        self.logger.info(f"Installing REVERSE flow on DPID {datapath.id:016x}: "
                         f"FROM {self.honeypot_ip} (MAC {self.honeypot_mac}) TO {attacker_ip} (MAC {attacker_mac} via port {port_to_attacker}), "
                         f"APPEARING AS FROM {original_target_ip} (MAC {original_target_mac})")
        match_reverse = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            eth_src=self.honeypot_mac, # Match packets physically from honeypot
            ipv4_src=self.honeypot_ip,
            eth_dst=attacker_mac,      # Match packets physically to attacker's MAC on this switch
            ipv4_dst=attacker_ip
        )
        actions_reverse = [
            parser.OFPActionSetField(eth_src=original_target_mac),
            parser.OFPActionSetField(ipv4_src=original_target_ip),
            parser.OFPActionOutput(port_to_attacker)
        ]
        self.add_flow(datapath, 101, match_reverse, actions_reverse, idle_timeout=300, hard_timeout=600, cookie=0x2B)

    def _block_ip(self, datapath, src_ip_to_block):
        parser = datapath.ofproto_parser
        self.logger.warning(f"Installing BLOCK flow on DPID {datapath.id:016x} for all traffic from IP: {src_ip_to_block}")
        match_block = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip_to_block)
        actions_block = []
        self.add_flow(datapath, 500, match_block, actions_block, hard_timeout=3600, cookie=0x2C)

    # --- Traffic Monitoring Methods ---
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()): self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug(f'Sending stats request to: {datapath.id:016x}')
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, 0, datapath.ofproto.OFPTT_ALL, datapath.ofproto.OFPP_ANY, datapath.ofproto.OFPG_ANY, 0, 0, parser.OFPMatch())
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dp_id_str = f"{ev.msg.datapath.id:016x}"
        self.logger.debug(f"Received flow stats from DPID: {dp_id_str} (Raw count: {len(body)})")
        active_flows = [flow for flow in body if flow.priority >= 1]
        if not active_flows:
            self.logger.debug(f"No active flows (priority >=1) to report for DPID: {dp_id_str}")
            return

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
                    if hasattr(instruction, 'actions') and instruction.actions:
                        for action in instruction.actions: # Should be only one OFPActionOutput in simple flows
                            if action.type == ofproto_v1_3.OFPAT_OUTPUT: # Check action type
                                out_port_field_val = (f"{action.port:x}" if isinstance(action.port, int) else str(action.port))
                                break # Found the output port
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
                self.logger.debug(f"PortStat Line: {msg_line}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(msg_line.encode('utf-8'), (TELEGRAF_UDP_IP, TELEGRAF_UDP_PORT))
            except Exception as e:
                self.logger.error(f"Error sending port stat: {e} for msg: '{locals().get('msg_line', 'FORMAT_ERROR')}'")

    # --- Main Packet-In Handler ---
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

        # Learn source MAC to port
        # Avoid learning MACs from the Snort mirror port on the mirror switch
        is_from_snort_mirror_port_on_mirror_switch = False
        if dpid == self.mirror_switch_dpid and in_port == self.mirror_to_host_snort_port:
            is_from_snort_mirror_port_on_mirror_switch = True
            self.logger.debug(f"Packet-in on DPID {dpid:016x} from Snort mirror port {in_port}. Not learning MAC {src_mac}.")

        if not is_from_snort_mirror_port_on_mirror_switch:
            if self.mac_to_port[dpid].get(src_mac) != in_port:
                self.mac_to_port[dpid][src_mac] = in_port
                self.logger.debug(f"Learned MAC {src_mac} on switch {dpid:016x} port {in_port}")

        # Learn IP to MAC mapping (globally for simplicity, or could be per-DPID)
        if ip_pkt:
            if src_mac and not src_mac.startswith("33:33:") and src_mac != "ff:ff:ff:ff:ff:ff": # Avoid multicast/broadcast MACs
                self.ip_to_mac_map[ip_pkt.src] = src_mac
            # Learning dst_ip to dst_mac from packet-ins can be tricky due to broadcasts/gateways
            # It's often better to learn this when a host ARPs or replies.
            # For now, primarily relying on learning source IP/MAC.

            src_ip = ip_pkt.src
            # Check if attacker IP is already flagged for redirection or blocking.
            # If so, specific flows should handle their traffic. This packet-in is likely for a new, unhandled flow from them.
            # The alert handler (_snort_alert_handler) is responsible for adding/refreshing these high-priority flows.

        # --- L2 Forwarding & Mirroring ---
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Mirror traffic on the designated mirror_switch_dpid to the host_snort_port
        if dpid == self.mirror_switch_dpid and \
           self.mirror_to_host_snort_port is not None and \
           in_port != self.mirror_to_host_snort_port: # Don't mirror packets from the Snort tap itself

            is_already_mirrored_or_redundant = False
            if out_port == self.mirror_to_host_snort_port: # Already going to Snort port
                is_already_mirrored_or_redundant = True
            # If flooding, it will go to snort_port unless snort_port is in_port.
            # To be absolutely sure, add it unless it's the primary out_port.
            
            if not is_already_mirrored_or_redundant:
                # Ensure mirror action isn't a duplicate if actions already had it for some reason
                # This check is a bit simplistic if actions could have multiple OFPActionOutput
                if not any(isinstance(a, parser.OFPActionOutput) and a.port == self.mirror_to_host_snort_port for a in actions):
                    self.logger.debug(f"DPID {dpid:016x}: Adding mirror action to snort port {self.mirror_to_host_snort_port} for {src_mac}->{dst_mac} (in_port {in_port}, out_port {out_port})")
                    actions.append(parser.OFPActionOutput(self.mirror_to_host_snort_port))

        # Install L2 flow if destination is known (not flooding) and not ARP
        if out_port != ofproto.OFPP_FLOOD and eth_pkt.ethertype != ether_types.ETH_TYPE_ARP:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            # If ip_pkt exists, you could add L3 match fields for more specific L2 flows if desired
            # if ip_pkt:
            #    match.append_field(ofproto.OXM_OF_IPV4_SRC, ip_pkt.src)
            #    match.append_field(ofproto.OXM_OF_IPV4_DST, ip_pkt.dst)

            buffer_id_to_use = msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER else None
            self.add_flow(datapath, 1, match, actions, buffer_id=buffer_id_to_use, idle_timeout=60, hard_timeout=180)
            
            # If packet was buffered at switch and used for flow_mod (buffer_id_to_use was not None),
            # then no PacketOut is strictly needed. Otherwise, or to be safe for OFP_NO_BUFFER:
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
                out_msg = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out_msg)
            return # Packet processing complete for this path

        # If flooding, send PacketOut with current actions (which includes OFPP_FLOOD and possibly mirror)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out_msg = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out_msg)