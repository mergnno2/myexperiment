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
import pdb
import csv
import ryu.lib.packet.ipv4
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib import packet
from ryu.lib.packet import ether_types

import datetime
import re
import time


class Host(object):
    def __init__(self, IP, ts, tl, Td, ratio, alpha, suspicious_type):
        self.IP = IP
        # Td is the dynamic time window's length for different host.
        # default is 120s(2 minutes)
        self.Td = Td
        # alpha is the counter of each host, it is for counting the abnormal flows
        # that appears in the same time window
        self.alpha = alpha
        # set the suspicious type of the host. Such as RST suspicious and ICMP suspicious
        self.suspicious_type = suspicious_type
        # window_sample will record the exact time intervals between every two abnormal flows.
        self.window_sample = []
        self.window_sample.append(self.Td)
        # window_ewma will generate the ewma value based on the window_sample list
        self.window_ewma = []
        # '0' means the time stamp of the estimated probe interval
        self.window_ewma.append(['0', self.Td])

        self.detected_flows = 0
        self.detected_flows_flush = 0

        # starts of the one time window
        self.ts = ts
        # last seen time stamp
        self.tl = tl
        # likelihood ratio of sequential test
        self.ratio = ratio


class SimpleSwitchWithScanDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchWithScanDetection, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        self.logger.info("\n--------Start of Initializing--------")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        # step1, once the switch is connected, send default flow entries and group entries.

        if ev.msg.datapath.id == 4:
            # table 0
            # default flow entries
            # 1.table-miss entry
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            self.add_flow(datapath=datapath, table_id=0, priority=0, match=match, inst=inst)
            self.logger.info("--------End of Initializing--------")
            return

        match = parser.OFPMatch(in_port=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions), parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath=datapath, table_id=0, priority=1, match=match, inst=inst)

        match = parser.OFPMatch(in_port=2)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions), parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath=datapath, table_id=0, priority=1, match=match, inst=inst)

        match = parser.OFPMatch(in_port=3)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions), parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath=datapath, table_id=0, priority=1, match=match, inst=inst)

        # table 1 table-miss entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.add_flow(datapath=datapath, table_id=1, priority=0, match=match, inst=inst)
        self.logger.info("--------End of Initializing--------")

    def add_flow(self, datapath, table_id, priority, match, inst, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def handle_simple_switch(self, ev, table_id):
        self.logger.info("--------Start of simple switch function--------")
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = ryu.lib.packet.packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        # print("-----",pkt.get_protocol(ipv4.ipv4))

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        # if the dict has dpid, return the values.
        # if not, set default values to the given dpid.
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            self.logger.info("dst found")
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.logger.info("Non-OFPP FLOOD")
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                # here the table id is 1, because it is the forwarding table
                self.add_flow(datapath=datapath, table_id=table_id, priority=1,
                              match=match, inst=inst, buffer_id=msg.buffer_id)
                return
            else:
                self.add_flow(datapath=datapath, table_id=table_id, priority=1,
                              match=match, inst=inst)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.logger.info("packet_out msg sent")
        self.logger.info("--------End of simple switch function--------")
        return

    def print_pkt_in_count(self, min_interval):
        global pkt_in_counter
        global total_collected_counter
        global scan_related_counter
        global total_entries

        with open("/home/ming/Desktop/graduation_project/detection_output/count_pkt_in.csv",
                  'a', newline="") as pkn_in_count_file:
            writer = csv.writer(pkn_in_count_file)
            pkt_in_counter_rows = [
                [time.strftime("%Y-%m-%d %H:%M:%S"), time.time()],
                ["pkt_in_counter", pkt_in_counter],
                ["minutes:", min_interval],
                ["total_collected_counter:", total_collected_counter],
                ["scan_related_counter:", scan_related_counter],
                ["total_entries:", len(total_entries)]
            ]
            writer.writerows(pkt_in_counter_rows)
        pkt_in_counter = 0
        return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        # count the packet in message count per minute
        global timing_min
        global pkt_in_counter
        global total_collected_counter
        global edge_switches
        global scan_related_counter
        global total_entries

        pkt_in_counter = pkt_in_counter + 1
        if time.localtime(time.time()).tm_min != timing_min:
            self.print_pkt_in_count(min_interval=abs(time.localtime(time.time()).tm_min - timing_min))
            timing_min = time.localtime(time.time()).tm_min

        msg = ev.msg
        pkt = ryu.lib.packet.packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src_mac = eth.src
        dst_mac = eth.dst

        pkt = ryu.lib.packet.packet.Packet(msg.data)
        tcp_pkt = pkt.get_protocols(ryu.lib.packet.tcp.tcp)
        icmp_pkt = pkt.get_protocols(ryu.lib.packet.icmp.icmp)
        if tcp_pkt:
            dst_port = str(tcp_pkt[0].dst_port)
        else:
            dst_port = "-1"

        if ev.msg.datapath.id == 4:
            self.handle_simple_switch(ev=ev, table_id=0)
        else:
            # it is from the edge switch
            if ev.msg.table_id == 0:
                if [src_mac, dst_mac, dst_port] not in total_entries:
                    total_entries.append([src_mac, dst_mac, dst_port])
                total_collected_counter = total_collected_counter + 1
                if str(src_mac) == "00:00:00:00:00:01" or str(dst_mac) == "00:00:00:00:00:01":
                    scan_related_counter = scan_related_counter + 1
            else:
                self.handle_simple_switch(ev=ev, table_id=1)

        return


hosts = []  # record the hosts which is related to abnormal flows and ready to detected by the algorithm
active_hosts = []
suspicious_flows_rows = []
ewma_rows = {}
detection_log_rows = []
edge_switches = []

theta0 = 0.8
theta1 = 0.2
eta0 = 0.01
eta1 = 99
beta = 0.2  # beta is the attribute of the EWMA algorithm
activity_end_test_multiplier = 35  # multiplier to test if a scan has reached its end
alpha_max = 3  # max value of the suspicious counter in per time window
alpha_ultra = 10  # to fit the fast scanning attack
default_window_len = 150
min_window_len = 1  # second
max_window_len = 1800
timing_hour = time.localtime(time.time()).tm_hour  # print time information
timing_min = time.localtime(time.time()).tm_min
timing_min_temp = time.localtime(time.time()).tm_min
pkt_in_counter = 0
total_collected_counter = 0
scan_related_counter = 0

right_detect_counter = 0
false_detect_counter = 0
total_entries = []

# record window_ewma and all suspicious flows with timestamp here.
mutex_to_print_data = 1
