# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Inspirowane https://github.com/knetsolutions/learn-sdn-with-ryu/tree/master/ryu-exercises
# ex3_L4Match_switch.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

TABLE_0 = 0 
TABLE_1 = 1
TABLE_2 = 2

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs): 
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.table0 = []
        self.table1 = []
        self.table2 = []
        self.table0_max_entries = 5000 # zmieniac
        self.table1_max_entries = 5000 # zmieniac
        self.table2_max_entries = 0
        self.current_switch = 0
        self.switch1_active_flows_t0 = 0
        self.switch1_active_flows_t1 = 0
        self.switch1_active_flows_t2 = 0
        self.switch2_active_flows_t0 = 0
        self.switch2_active_flows_t1 = 0
        self.switch2_active_flows_t2 = 0
        self.switch3_active_flows_t0 = 0
        self.switch3_active_flows_t1 = 0
        self.switch3_active_flows_t2 = 0
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.add_goto_tables(datapath)
        
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, table_id=0,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, table_id=0,
                                    instructions=inst)
            
        datapath.send_msg(mod)    
        
    def add_entries_with_limit(self, datapath, priority, match, actions, table, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        
        if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, table_id = table,
                                        match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, table_id = table,
                                    instructions=inst)
           
        datapath.send_msg(mod)     
        
    def add_miss_entry(self, datapath, priority, match, action, table, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if table < 2:
            inst = [parser.OFPInstructionGotoTable(table + 1)]
            if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, table_id = table,
                                        match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, table_id = table,
                                        instructions=inst)
            datapath.send_msg(mod)
            
        elif table == 2:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
            if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, table_id = table,
                                        match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, table_id = table,
                                        instructions=inst)
            datapath.send_msg(mod)

    def add_goto_tables(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        
        table0 = TABLE_0
        table1 = TABLE_1
        table2 = TABLE_2
        
        action0 = [parser.OFPActionOutput(ofproto.OFPCML_NO_BUFFER)]
        self.add_miss_entry(datapath, 0, match, action0,  table0)
        self.add_miss_entry(datapath, 0, match, action0,  table1)
        action2 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_miss_entry(datapath, 0, match, action2, table2)

    def send_table_stats_requests(self, datapath):
        ofp_parser = datapath.ofproto_parser        
        req = ofp_parser.OFPTableStatsRequest(datapath,0)
        datapath.send_msg(req)
        #self.logger.info('TABLE 0: {}'.format(self.table0))
        
    @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
    def desc_table_reply_handler(self,ev):    
        tables = []
        active_count_table0 = 0
        active_count_table1 = 0
        active_count_table2 = 0
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        for stat in ev.msg.body:
            if stat.table_id < 4:
                tables.append('table_id=%d active_count=%d matched_count=%d' %
                            (stat.table_id, stat.active_count, stat.matched_count))
                if stat.table_id == 0:
                    active_count_table0 = stat.active_count
                    self.table0.append(active_count_table0)
                elif stat.table_id == 1:
                    active_count_table1 = stat.active_count
                    self.table1.append(active_count_table1)
                elif stat.table_id == 2:
                    active_count_table2 = stat.active_count
                    self.table2.append(active_count_table2)
        if dpid == 1:
            self.switch1_active_flows_t0 = active_count_table0
            self.switch1_active_flows_t1 = active_count_table1
            self.switch1_active_flows_t2 = active_count_table2
        elif dpid == 2:
            self.switch2_active_flows_t0 = active_count_table0
            self.switch2_active_flows_t1 = active_count_table1
            self.switch2_active_flows_t2 = active_count_table2
        elif dpid == 3:
            self.switch3_active_flows_t0 = active_count_table0
            self.switch3_active_flows_t1 = active_count_table1
            self.switch3_active_flows_t2 = active_count_table2
        #self.logger.info("Current switch: %s", datapath.id)  
        #self.logger.info('TableStats: %s', tables)
    
    def send_features_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)
         

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.current_switch = dpid

        self.send_table_stats_requests(datapath) 
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD 

        actions = [parser.OFPActionOutput(out_port)] 

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
            
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port,)
            
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port,)            

                #self.logger.info("switch from before ? %s", self.current_switch)
                if self.current_switch == 1:
                        active_flows_t0 = self.switch1_active_flows_t0
                        active_flows_t1 = self.switch1_active_flows_t1
                elif self.current_switch == 2:
                        active_flows_t0 = self.switch2_active_flows_t0
                        active_flows_t1 = self.switch2_active_flows_t1
                elif self.current_switch == 3:
                        active_flows_t0 = self.switch3_active_flows_t0
                        active_flows_t1 = self.switch3_active_flows_t1

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    if active_flows_t0 < self.table0_max_entries:
                        self.add_entries_with_limit(datapath, 1, match, actions, TABLE_0, msg.buffer_id)
                    elif active_flows_t0  >= self.table0_max_entries and active_flows_t1 < self.table1_max_entries:
                        if protocol == in_proto.IPPROTO_TCP:
                            t = pkt.get_protocol(tcp.tcp)
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_dst=t.dst_port,)
                            self.add_entries_with_limit(datapath, 1, match, actions, TABLE_1, msg.buffer_id)
                        elif protocol == in_proto.IPPROTO_UDP:
                            u = pkt.get_protocol(udp.udp)
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_dst=u.dst_port,)
                            self.add_entries_with_limit(datapath, 1, match, actions, TABLE_1, msg.buffer_id)
                        else:
                            self.add_entries_with_limit(datapath, 1, match, actions, TABLE_1, msg.buffer_id)
                else:
                    if active_flows_t0 < self.table0_max_entries:
                        self.add_entries_with_limit(datapath, 1, match, actions, TABLE_0)
                    elif active_flows_t0  >= self.table0_max_entries and active_flows_t1 < self.table1_max_entries:
                        if protocol == in_proto.IPPROTO_TCP:
                            t = pkt.get_protocol(tcp.tcp)
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_dst=t.dst_port,)
                            self.add_entries_with_limit(datapath, 1, match, actions, TABLE_1)
                        elif protocol == in_proto.IPPROTO_UDP:
                            u = pkt.get_protocol(udp.udp)
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_dst=u.dst_port,)
                            self.add_entries_with_limit(datapath, 1, match, actions, TABLE_1)
                        else:
                            self.add_entries_with_limit(datapath, 1, match, actions, TABLE_1)
                  
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)