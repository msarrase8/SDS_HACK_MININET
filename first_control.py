from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

class HoneypotController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HoneypotController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.honeypot_ip = '10.0.0.4'
        self.target_ip = '10.0.0.13'  # IP a la que se redirigirá tráfico

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Enviar todo al controlador por defecto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                     actions)]

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

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        in_port = msg.match['in_port']
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        dst = eth.dst
        src = eth.src
        self.mac_to_port[dpid][src] = in_port

        # --- Redirección al honeypot si el destino es el servidor objetivo ---
        if ip_pkt:
            dst_ip = ip_pkt.dst

            if dst_ip == self.target_ip:
                self.logger.info("Redirigiendo tráfico destinado a %s hacia honeypot %s", dst_ip, self.honeypot_ip)
                match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
                actions = [
                    parser.OFPActionSetField(ipv4_dst=self.honeypot_ip),
                    parser.OFPActionSetField(eth_dst='00:00:00:00:00:04'),
                    parser.OFPActionOutput(ofproto.OFPP_FLOOD)
                ]
                self.add_flow(datapath, 20, match, actions)
                return  # No reenviamos este paquete

        # --- Comportamiento normal L2 ---
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
        self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)
