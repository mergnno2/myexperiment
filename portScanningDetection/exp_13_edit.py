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


def check_suspicious(ev):
    # check one flow if it is a suspicious flow by checking the flags

    # return types:
    # 0 - not suspicious
    # 1 - RST error
    # 2 - ICMP error
    msg = ev.msg
    pkt = ryu.lib.packet.packet.Packet(msg.data)
    tcp_pkt = pkt.get_protocols(ryu.lib.packet.tcp.tcp)
    icmp_pkt = pkt.get_protocols(ryu.lib.packet.icmp.icmp)
    if tcp_pkt and tcp_pkt[0].has_flags(ryu.lib.packet.tcp.TCP_RST):
        return 1
    elif icmp_pkt and icmp_pkt[0].type == ryu.lib.packet.icmp.ICMP_DEST_UNREACH:
        return 2
    return 0


def sequential_test(success_num, failed_num, host):
    while success_num > 0:
        host.ratio = host.ratio * (theta1 / theta0)
        success_num = success_num - 1
    host.ratio = host.ratio * host.alpha * ((1 - theta1) / (1 - theta0))
    if host.ratio == 0:
        host.ratio = 1
    if host.ratio > eta1:
        return 1
    elif host.ratio < eta0:
        return 2
    return 0


def print_data():
    filepath_basic = "/home/ming/Desktop/graduation_project/detection_output/"
    filepath_subfiles = [
        'suspicious_flows.csv',
        'right_false_detected.csv',
        'detection_log.csv'
    ]
    filepath_total = []

    global suspicious_flows_rows
    global ewma_rows
    global detection_log_rows
    global right_detect_counter
    global false_detect_counter
    global start_test

    for subfile in filepath_subfiles:
        filepath_total.append(filepath_basic + subfile)

    # open the original csv data file
    with open(filepath_total[0], 'a', newline="") as suspicious_flows_file:
        writer = csv.writer(suspicious_flows_file)
        writer.writerows(suspicious_flows_rows)

    # write ewma
    keys = ewma_rows.keys()
    for k in keys:
        rows_to_write = ewma_rows.get(k)
        with open(filepath_basic + str(k) + ".csv", 'w', newline="") as ewma_file:
            writer = csv.writer(ewma_file)
            writer.writerows(rows_to_write)

    with open(filepath_total[1], 'a', newline="") as right_false_file:
        writer = csv.writer(right_false_file)
        right_false_row = ["right detected", right_detect_counter, "false detected", false_detect_counter]
        writer.writerow(right_false_row)

    with open(filepath_total[2], 'a', newline="") as detection_log_file:
        writer = csv.writer(detection_log_file)
        writer.writerows(detection_log_rows)

    suspicious_flows_rows.clear()
    detection_log_rows.clear()

    return


def detect_abnormal(ev):
    global right_detect_counter
    global false_detect_counter
    global detection_log_rows

    global timing_min_temp
    if time.localtime(time.time()).tm_min != timing_min_temp:
        print_data()
        timing_min_temp = time.localtime(time.time()).tm_min

    msg = ev.msg
    pkt = ryu.lib.packet.packet.Packet(msg.data)
    ipv4_pkt = pkt.get_protocols(ryu.lib.packet.ipv4.ipv4)[0]

    tcp_pkt = pkt.get_protocols(ryu.lib.packet.tcp.tcp)
    icmp_pkt = pkt.get_protocols(ryu.lib.packet.icmp.icmp)

    # timeStamp = get_time(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    timeStamp = time.time()

    # the main process of the algorithm using dynamic time window
    # suspicious type is used to identify different scanning activities
    suspicious_type = check_suspicious(ev=ev)
    if suspicious_type == 0:
        # it's not a suspicious flow
        return
    else:
        # we don't care if it is 1 or 2 type
        IP = ipv4_pkt.dst
    # it is a suspicious flow, handle this flow by detection algorithm

    # first check if the hosts[] has already recorded the srcIP and suspicious type of this flow
    isNew = True
    i = 0
    while i < len(hosts):
        if hosts[i].IP == IP and hosts[i].suspicious_type == suspicious_type:
            # before detection, check if current host has finished an attack before
            if len(hosts[i].window_ewma) > 5:
                summery = 0
                ewma_index = 0
                while ewma_index < 5:
                    summery = summery + hosts[i].window_ewma[ewma_index][1]
                    ewma_index = ewma_index + 1
                activity_end_test = summery / len(hosts[i].window_ewma)
            else:
                summery = 0
                for item in hosts[i].window_ewma:
                    summery = summery + item[1]
                activity_end_test = summery / len(hosts[i].window_ewma)
            if timeStamp - hosts[i].tl > activity_end_test_multiplier * activity_end_test:
                hosts.__delitem__(i)
                isNew = True
            else:
                current_host = hosts[i]
                isNew = False
        i = i + 1

    if isNew:
        current_host = Host(IP=IP, ts=timeStamp, tl=timeStamp, Td=default_window_len,
                            ratio=1, alpha=1, suspicious_type=suspicious_type)
        hosts.append(current_host)
        # and if it's the first abnormal flow of the given host, do nothing and waiting for second one.
        return

    # record the abnormal flow
    # output the suspicious flows file
    if suspicious_type == 1:
        suspicious_flows_rows.append(
            [time.strftime("%Y-%m-%d %H:%M:%S"), time.time(),
             str(suspicious_type),
             ipv4_pkt.dst,
             tcp_pkt[0].dst_port]
        )
    elif suspicious_type == 2:
        suspicious_flows_rows.append(
            [time.strftime("%Y-%m-%d %H:%M:%S"), time.time(),
             str(suspicious_type),
             ipv4_pkt.dst,
             '']
        )
    else:
        suspicious_flows_rows.append(
            [time.strftime("%Y-%m-%d %H:%M:%S"), time.time(),
             '0',
             current_host.IP,
             '']
        )

    # the host of this abnormal flow has already appears before, then run the algorithm
    current_host.detected_flows_flush = current_host.detected_flows_flush + 1
    ti = timeStamp
    delta_t = ti - current_host.ts
    if delta_t < current_host.Td and current_host.alpha < alpha_ultra:
        # the time window is not over yet.

        # append the sample window length according to the time stamp of current flow
        current_host.window_sample.append(ti - current_host.tl)
        # append the EWMA window length according to the EWMA algorithm
        ewma_value = (1 - beta) * current_host.window_ewma[-1][1] + beta * current_host.window_sample[-1]
        # make sure the ewma value is limited by the range of [5s,1800s]
        if ewma_value < min_window_len:
            ewma_value = min_window_len
        elif ewma_value > max_window_len:
            ewma_value = max_window_len
        current_host.window_ewma.append([time.time(), ewma_value])

        # record the ewma values to print
        ewma_result = ewma_rows.get(current_host.IP)
        if ewma_result is None:
            new_ewma_rows = [current_host.IP, [int(time.time()), ewma_value]]
            ewma_rows.update({current_host.IP: new_ewma_rows})
        else:
            ewma_result.append([int(time.time()), ewma_value])
            ewma_rows.update({current_host.IP: ewma_result})

        # update the last seen time stamp of the abnormal flow that caused by the host
        current_host.tl = ti

        # count the abnormal counter(alpha) for the given host
        current_host.alpha = current_host.alpha + 1

        # fix the ewma bug here. if alpha is larger than 15, we should consider if the attacker is running a faster scan
        # then we should adjust the window length immediately.
        if current_host.alpha > alpha_max:
            # turn the current window length Td into the newest ewma window length
            current_host.Td = current_host.window_ewma[-1][1]

    elif current_host.alpha >= alpha_ultra:
        # it is attacker
        detection_log_rows.append(
            [time.strftime("%Y-%m-%d %H:%M:%S"), current_host.IP]
        )

        if current_host.IP == "10.0.0.1":
            right_detect_counter = right_detect_counter + current_host.detected_flows_flush
        else:
            false_detect_counter = false_detect_counter + current_host.detected_flows_flush

        with open("/home/ming/Desktop/graduation_project/detection_output/detected_flows.csv",
                  'a', newline="") as detected_flows_file:
            writer = csv.writer(detected_flows_file)
            detected_flows_row = [
                current_host.IP,
                current_host.detected_flows_flush,
                time.strftime("%Y-%m-%d %H:%M:%S")
            ]
            writer.writerow(detected_flows_row)

        current_host.detected_flows_flush = 0

        print("&&&&&&&&&  Scanning Activity Detected!  &&&&&&&&&", str(current_host.IP))
        # it is an abnormal host, we have made decision.
        current_host.ratio = 1

        # append the sample window length according to the time stamp of current flow
        current_host.window_sample.append(ti - current_host.tl)
        # append the EWMA window length according to the EWMA algorithm
        ewma_value = (1 - beta) * current_host.window_ewma[-1][1] + beta * current_host.window_sample[-1]
        # make sure the ewma value is limited by the range of [5s,1800s]
        if ewma_value < min_window_len:
            ewma_value = min_window_len
        elif ewma_value > max_window_len:
            ewma_value = max_window_len
        current_host.window_ewma.append([time.time(), ewma_value])

        # record the ewma values to print
        ewma_result = ewma_rows.get(current_host.IP)
        if ewma_result is None:
            new_ewma_rows = [current_host.IP, [int(time.time()), ewma_value]]
            ewma_rows.update({current_host.IP: new_ewma_rows})
        else:
            ewma_result.append([int(time.time()), ewma_value])
            ewma_rows.update({current_host.IP: ewma_result})

        current_host.ts = time.time()
        current_host.tl = ti
        current_host.Td = ewma_value
        current_host.alpha = 1

    else:  # delta_t>current_host.Td

        # generate(get) the newest ewma value of the time window's length from window_ewma
        n_ewma = current_host.window_ewma[-1][1]
        success_num = int((delta_t - current_host.Td) / n_ewma)
        failed_num = 1
        # according to three attributes:success_num,failed_num and alpha, calculate the likelihood ratio
        test_result = sequential_test(success_num=success_num, failed_num=failed_num, host=current_host)
        if test_result == 1:
            # need to output:
            # 1.src_ip,
            # 2.dst_ip,
            # 3.src_port,
            # 4.dst_port,
            # 5.suspicious type
            # 6.time stamp

            detection_log_rows.append(
                [time.strftime("%Y-%m-%d %H:%M:%S"), current_host.IP]
            )

            if current_host.IP == "10.0.0.1":
                right_detect_counter = right_detect_counter + current_host.detected_flows_flush
            else:
                false_detect_counter = false_detect_counter + current_host.detected_flows_flush

            with open("/home/ming/Desktop/graduation_project/detection_output/detected_flows.csv",
                      'a', newline="") as detected_flows_file:
                writer = csv.writer(detected_flows_file)
                detected_flows_row = [
                    current_host.IP,
                    current_host.detected_flows_flush,
                    time.strftime("%Y-%m-%d %H:%M:%S")
                ]
                writer.writerow(detected_flows_row)

            current_host.detected_flows_flush = 0

            print("&&&&&&&&&  Scanning Activity Detected!  &&&&&&&&&", str(current_host.IP))
            # it is an abnormal host, we have made decision.
            current_host.ratio = 1
        # append the sample window length according to the time stamp of current flow
        current_host.window_sample.append(ti - current_host.tl)
        # append the EWMA window length according to the EWMA algorithm
        ewma_value = (1 - beta) * current_host.window_ewma[-1][1] + beta * current_host.window_sample[-1]
        # make sure the ewma value is limited by the range of [5s,1800s]
        if ewma_value < min_window_len:
            ewma_value = min_window_len
        elif ewma_value > max_window_len:
            ewma_value = max_window_len
        current_host.window_ewma.append([time.time(), ewma_value])

        # record the ewma values to print
        ewma_result = ewma_rows.get(current_host.IP)
        if ewma_result is None:
            new_ewma_rows = [current_host.IP, [int(time.time()), ewma_value]]
            ewma_rows.update({current_host.IP: new_ewma_rows})
        else:
            ewma_result.append([int(time.time()), ewma_value])
            ewma_rows.update({current_host.IP: ewma_result})

        current_host.ts = current_host.ts + current_host.Td + success_num * n_ewma
        current_host.tl = ti
        current_host.Td = ewma_value
        current_host.alpha = 1

    return


def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp


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
        # table 0 (in_port table):
        # default flow entries
        # 1.table-miss entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.add_flow(datapath=datapath, table_id=0, priority=0, match=match, inst=inst)
        self.logger.info("Table-0-Table-miss set.")

        # table 1 (collection table):
        # default flow entries
        # 2.table-miss entry
        match = parser.OFPMatch()
        # instruction is go to table 2.
        inst = [parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath=datapath, table_id=1, priority=0, match=match, inst=inst)
        self.logger.info("Table-1-Table-miss set.")

        # 3.Table-2 (forwarding flow table) Table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.add_flow(datapath=datapath, table_id=2, priority=0, match=match, inst=inst)
        self.logger.info("Table-2-Table-miss set.")

        self.logger.info("--------End of Initializing--------")

    def set_in_port_entry(self, ev, in_port_type, table_id):
        datapath = ev.msg.datapath
        in_port = ev.msg.match['in_port']
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port)
        if in_port_type == 1:
            # this in_port is connected to network host
            # instruction is go to table 1.
            inst = [parser.OFPInstructionGotoTable(1)]
        elif in_port_type == 2:
            # this in_port is connected to switch
            inst = [parser.OFPInstructionGotoTable(2)]
        # set this flow entry
        self.add_flow(datapath=datapath, table_id=table_id, priority=1, match=match, inst=inst)

    def set_collection_entry(self, ev, table_id):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 1.ICMP error message entry
        # 0x0800 -> ipv4
        # 0x01 -> ICMP
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x01, icmpv4_type=0x03)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # instructions are:
        # (1) clone the packet and output to the controller.
        # (2) go to table 1 (simple switch - forwarding table)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions), parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath=datapath, table_id=table_id, priority=1, match=match, inst=inst)
        print("Table-1-ICMP-error set.")

        # 2.1 TCP URG entry
        # 0x0800 -> ipv4
        # 0x06 -> IP
        # 0x02b -> URG+PSH+SYN+FIN flag
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_flags=0x020)
        # instruction is go to table 2.
        inst = [parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath=datapath, table_id=table_id, priority=1, match=match, inst=inst)
        print("Table-1-TCP-URG set.")
        # 2.2 TCP PSH entry
        # 0x0800 -> ipv4
        # 0x06 -> IP
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_flags=0x008)
        # instruction is go to table 2.
        inst = [parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath=datapath, table_id=table_id, priority=1, match=match, inst=inst)
        print("Table-1-TCP-PSH set.")
        # 2.3 TCP FIN entry
        # 0x0800 -> ipv4
        # 0x06 -> IP
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_flags=0x001)
        # instruction is go to table 1.
        inst = [parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath=datapath, table_id=table_id, priority=1, match=match, inst=inst)
        print("Table-1-TCP-FIN set.")

        # 3.1 TCP RST+ACK entry
        # 0x0800 -> ipv4
        # 0x06 -> IP
        # 0x014 -> RST+ACK flag
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_flags=0x014)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # instructions are:
        # (1) clone the packet and output to the controller.
        # (2) go to table 1 (simple switch - forwarding table)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions), parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath=datapath, table_id=table_id, priority=1, match=match, inst=inst)
        print("Table-1-TCP-RST+ACK set")

        # 3.2 TCP RST entry
        # 0x0800 -> ipv4
        # 0x06 -> IP
        # 0x004 -> RST flag
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_flags=0x004)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # instructions are:
        # (1) clone the packet and output to the controller.
        # (2) go to table 1 (simple switch - forwarding table)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions), parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath=datapath, table_id=table_id, priority=1, match=match, inst=inst)
        print("Table-1-TCP-RST set.")

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

    def handle_scan_detection(self, ev):
        # self.logger.info("--------Start of scan detection--------")
        # write scan detection method here.
        detect_abnormal(ev=ev)
        # print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        # self.logger.info("--------End of scan detection--------")
        return

    def print_pkt_in_count(self, min_interval):
        global pkt_in_counter
        global total_pkt_in_counter

        with open("/home/ming/Desktop/graduation_project/detection_output/count_pkt_in.csv",
                  'a', newline="") as pkn_in_count_file:
            writer = csv.writer(pkn_in_count_file)
            pkt_in_counter_rows = [
                ["Packet_in counter:", time.strftime("%Y-%m-%d %H:%M:%S"), time.time()],
                [pkt_in_counter, "minutes:", min_interval],
                ["total_pkt_in_counter:", total_pkt_in_counter]
            ]
            writer.writerows(pkt_in_counter_rows)
        pkt_in_counter = 0
        return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        # count the packet in message count per minute
        global timing_min
        global pkt_in_counter
        global total_pkt_in_counter
        global edge_switches
        total_pkt_in_counter = total_pkt_in_counter + 1
        pkt_in_counter = pkt_in_counter + 1
        if time.localtime(time.time()).tm_min != timing_min:
            self.print_pkt_in_count(min_interval=abs(time.localtime(time.time()).tm_min - timing_min))
            timing_min = time.localtime(time.time()).tm_min

        msg = ev.msg

        global active_hosts
        # source MAC address is no longer needed
        pkt = ryu.lib.packet.packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src_mac = eth.src

        if src_mac in active_hosts:
            # 1.we don't have to add this source IP
            # 2.we need to check out which table it comes from

            if ev.msg.table_id == 0:
                # it comes from the in_port table
                # this msg comes from the other switch
                # we need to set flow entry in table 0
                # match: in_port = in_port, action: goto table 2
                self.set_in_port_entry(ev=ev, in_port_type=2, table_id=0)
                self.handle_simple_switch(ev=ev, table_id=2)
            if ev.msg.table_id == 1:
                # this packet_in comes from the collection table
                # all the flows comes from the collection table would be suspicious flows
                self.handle_scan_detection(ev=ev)
            elif ev.msg.table_id == 2:
                self.handle_simple_switch(ev=ev, table_id=2)
        else:
            # 1.we need to record this IP
            active_hosts.append(src_mac)

            # 2.we need to set a flow entry in table 0
            self.set_in_port_entry(ev=ev, in_port_type=1, table_id=0)

            # 3.then we check if collection entries are set in edge switch
            if ev.msg.datapath.id not in edge_switches:
                # this switch is not recorded yet
                # 1.record this switch
                edge_switches.append(ev.msg.datapath.id)
                # 2.set collection entries to collect suspicious flows in collection table
                # match: 6 marking entries
                # action: (send to controller + goto table 2) or (goto table 2)
                self.set_collection_entry(ev=ev, table_id=1)

            # 4.forward this packet.
            self.handle_simple_switch(ev=ev, table_id=2)

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
total_pkt_in_counter = 0

right_detect_counter = 0
false_detect_counter = 0

# record window_ewma and all suspicious flows with timestamp here.
mutex_to_print_data = 1
