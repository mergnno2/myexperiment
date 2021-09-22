# This code refer to the paper "Detection of slow port scans in flow-based network traffic"
# The data set used by the above paper is also "CIDDS-001"
# Start date: 09.09.2021
import re
import pandas as pd
import time
import numpy as np
import csv


class Connection(object):
    def __init__(self, src, dst, last_seen_time, con_1, con_2):
        self.src = Target(src.IP, src.port)
        self.dst = Target(dst.IP, dst.port)
        self.last_seen_time = last_seen_time
        self.con_1 = con_1
        self.con_2 = con_2


class Target(object):
    def __init__(self, IP, port):
        self.IP = IP
        self.port = port


class Network_Event(object):
    def __init__(self, IP, ICMP, RST, RwA, NeIP, NeTCP):
        self.IP = IP
        self.ICMP = ICMP
        self.RST = RST
        self.RwA = RwA
        self.NeIP = NeIP
        self.NeTCP = NeTCP


def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp


def check_IP(IP):
    for event in network_events:
        if event.IP == IP:
            return False
    return True


def count_ICMP(srcIP, time_window):
    ICMP = 0
    for flow in time_window:
        if flow[5] == srcIP and re.search("3\.", flow[6]) != None:
            ICMP = ICMP + 1
    return ICMP


def count_RST(srcIP, time_window):
    # TCP flags : U A P R S F
    RST = 0
    diff_target = []
    for flow in time_window:
        if flow[2] == "UDP  ":
            continue
        if flow[3] == srcIP and re.search("A", flow[10]) == None:
            if len(diff_target) == 0:
                target = Target(IP=flow[5], port=flow[6])
                diff_target.append(target)
                continue
            isNew = True
            i = 0
            while i < len(diff_target):
                if flow[5] == diff_target[i].IP and flow[6] == diff_target[i].port:
                    isNew = False
                i = i + 1
            if isNew:
                target = Target(IP=flow[5], port=flow[6])
                diff_target.append(target)
    # 至此，统计完了所有srcIP发起的目标的集合   目标：（目的地址，目的端口） 并且这次连接是TCP连接的第一次握手
    # 接下来，统计所有target发到srcIP的流集合，看是否有R标志位，如果有，计数之
    i = 0
    while i < len(diff_target):
        for flow in time_window:
            if flow[3] == diff_target[i].IP and flow[4] == diff_target[i].port and flow[5] == srcIP:
                if re.search("R", flow[10]) != None:
                    RST = RST + 1
                    break
        i = i + 1
    return RST


def count_RwA(srcIP, time_window):
    RwA = 0
    diff_target = []
    for flow in time_window:
        if flow[2] == "ICMP  ":  # 不考虑ICMP报文的“是否响应”特点
            continue
        if re.search("\.", flow[5]) != None:
            dstIP = flow[5][0:3]
            if flow[3] == srcIP:
                if int(dstIP) >= 224 and int(dstIP) <= 239:
                    continue
                if re.search("255", flow[5]) != None:
                    continue
                if len(diff_target) == 0:
                    target = Target(IP=flow[5], port=flow[6])
                    diff_target.append(target)
                    continue
                isNew = True
                i = 0
                while i < len(diff_target):
                    if flow[5] == diff_target[i].IP and flow[6] == diff_target[i].port:
                        isNew = False
                    i = i + 1
                if isNew:
                    target = Target(IP=flow[5], port=flow[6])
                    diff_target.append(target)
        else:
            if flow[3] == srcIP:
                if len(diff_target) == 0:
                    target = Target(IP=flow[5], port=flow[6])
                    diff_target.append(target)
                    continue
                isNew = True
                i = 0
                while i < len(diff_target):
                    if flow[5] == diff_target[i].IP and flow[6] == diff_target[i].port:
                        isNew = False
                    i = i + 1
                if isNew:
                    target = Target(IP=flow[5], port=flow[6])
                    diff_target.append(target)

    # 至此，统计完了所有srcIP发起的目标的集合   目标：（目的地址，目的端口）
    # 接下来，统计srcIP没有收到响应的目标（target）数
    i = 0
    while i < len(diff_target):
        noAnswer = True
        for flow in time_window:
            if flow[3] == diff_target[i].IP and flow[4] == diff_target[i].port and flow[5] == srcIP:
                noAnswer = False
                break
        if noAnswer:
            RwA = RwA + 1
        i = i + 1
    return RwA


def count_NeIP(srcIP, time_window):
    NeIP = 0
    diff_IP = []
    for flow in time_window:
        if flow[3] != srcIP:
            continue
        if re.search("\.", flow[5]) != None:
            dstIP = flow[5][0:3]
            if int(dstIP) >= 224 and int(dstIP) <= 239:
                continue
            if re.search("255", flow[5]) != None:
                continue
            if flow[5] not in diff_IP:
                diff_IP.append(flow[5])
        else:
            if flow[5] not in diff_IP:
                diff_IP.append(flow[5])
    for ip in diff_IP:
        if re.search("_", ip) != None:
            continue
        if network_info.get(ip) == None:
            NeIP = NeIP + 1
    return NeIP


def count_NeTCP(srcIP, time_window):
    NeTCP = 0
    diff_target = []
    for flow in time_window:
        if flow[2] != "TCP  ":  # Without considering flows that is not a TCP connection.
            continue
        elif flow[3] == srcIP:
            if len(diff_target) == 0:
                target = Target(IP=flow[5], port=flow[6])
                diff_target.append(target)
                continue
            isNew = True
            i = 0
            while i < len(diff_target):
                if flow[5] == diff_target[i].IP and flow[6] == diff_target[i].port:
                    isNew = False
                i = i + 1
            if isNew:
                target = Target(IP=flow[5], port=flow[6])
                diff_target.append(target)
    # 至此，统计完了所有srcIP发起的目标的集合   目标：（目的地址，目的端口）
    # 接下来，查看所有的目标（目的地址，目的端口）能否在“网络信息”字典中查找到
    i = 0
    while i < len(diff_target):
        if network_info.get(diff_target[i].IP) != None:
            if diff_target[i].port not in network_info.get(diff_target[i].IP):
                NeTCP = NeTCP + 1
        i = i + 1
    return NeTCP


def hosts_per_window(time_window):
    hosts = []
    for flow in time_window:
        if flow[3] not in hosts:
            hosts.append(flow[3])
    return hosts


def update_ratio(event):
    ip = event.IP
    if srcIP_ratio.get(ip) == None:
        item = {ip: 1.0}
        srcIP_ratio.update(item)
    ratio = float(srcIP_ratio.get(ip))
    ai = event.ICMP + event.NeIP + event.NeTCP
    if ai > 0:
        ratio = ratio * ai * ((1 - theta1) / (1 - theta0))
    else:
        ratio = ratio * (theta1 / theta0)
    srcIP_ratio[ip] = float(ratio)
    return


def detect_abnormal(event):
    if srcIP_ratio.get(event.IP) == None:
        return
    else:
        if srcIP_ratio.get(event.IP) > eita1:
            print(flow_data[-1][-1][0])
            # print("Port scan attack caused by the host: " + event.IP)
            srcIP_ratio[event.IP] = 1.0
        elif srcIP_ratio.get(event.IP) < eita0:
            # This host is considered as a normal one.
            srcIP_ratio[event.IP] = 1.0
        else:
            # We can't make decision that if corresponding host is abnormal or normal.
            pass
    return


def generate_network_event(time_window):
    network_events.clear()
    hosts = hosts_per_window(time_window=time_window)
    for host in hosts:
        ICMP = count_ICMP(srcIP=host, time_window=time_window)
        # RST = count_RST(srcIP=host, time_window=time_window)
        RST = 0
        # RwA = count_RwA(srcIP=host, time_window=time_window)
        RwA = 0
        NeIP = count_NeIP(srcIP=host, time_window=time_window)
        NeTCP = count_NeTCP(srcIP=host, time_window=time_window)
        network_events.append(Network_Event(IP=host, ICMP=ICMP, RST=RST, RwA=RwA, NeIP=NeIP, NeTCP=NeTCP))
        # One network event that is related to the 'host' is well generated from the given time window.
        # Update the corresponding srcIP's ratio according to the current network event attributes.
        update_ratio(event=network_events[-1])
        detect_abnormal(event=network_events[-1])
    return


def update_network_info(flow):
    # update the parameter 'network_info' (which is a dictionary that recored the <ip,ports> information) here:
    if flow[2] != "TCP  ":
        return
    src = Target(IP=flow[3], port=flow[4])
    dst = Target(IP=flow[5], port=flow[6])
    T = get_time(row[0])
    result_src = network_info.get(src.IP)
    result_dst = network_info.get(dst.IP)
    if result_src != None and result_dst != None:
        # if <sip,spt> and <dip,dpt> has already both recorded, then do nothing.
        if src.port in result_src and dst.port in result_dst:
            return
    isNew = True
    i = 0
    while i < len(connections):
        if connections[i].src.IP == src.IP and connections[i].src.port == src.port \
                and connections[i].dst.IP == dst.IP and connections[i].dst.port == dst.port:
            isNew = False
            if re.search("A", flow[10]) != None and re.search("S", flow[10]) != None:
                connections[i].last_seen_time = T
            else:
                connections.__delitem__(i)
            return
        elif connections[i].src.IP == dst.IP and connections[i].src.port == dst.port \
                and connections[i].dst.IP == src.IP and connections[i].dst.port == src.port:
            isNew = False
            if re.search("A", flow[10]) != None and re.search("S", flow[10]) != None:
                if T - connections[i].last_seen_time > 6:
                    connections[i].src.IP = dst.IP
                    connections[i].src.port = dst.port
                    connections[i].dst.IP = src.IP
                    connections[i].dst.port = src.port
                else:
                    connections[i].con_2 = True
                    if result_src != None:
                        if src.port not in result_src:
                            result_src.append(src.port)
                            network_info.update({src.IP: result_src})
                    else:
                        src_ports = []
                        src_ports.append(src.port)
                        network_info.update({src.IP: src_ports})
                    if result_dst != None:
                        if dst.port not in result_dst:
                            result_dst.append(dst.port)
                            network_info.update({dst.IP: result_dst})
                    else:
                        dst_ports = []
                        dst_ports.append(dst.port)
                        network_info.update({dst.IP: dst_ports})
                    connections.__delitem__(i)
            else:
                connections.__delitem__(i)
            return
        i = i + 1
    if isNew and re.search("A", flow[10]) != None and re.search("S", flow[10]) != None:
        connections.append(Connection(src=src, dst=dst, last_seen_time=T, con_1=True, con_2=False))
    return


def update_network_info_for_failed_connection(flow):
    # this method is for those flows which are related to the failed connections between attacker and victim.
    # obviousily, victim didn't connect to the invalid TCP port on the attacker's machine, they just did the
    # regular response to them.
    # Therefore, any flows that include TCP flags 'A' are considered as normal ( in the case of only SYN scan exist.)
    if flow[2] != "TCP  " or re.search("A", flow[10]) == None:
        return
    dst = Target(IP=flow[5], port=flow[6])
    result = network_info.get(dst.IP)
    if result == None:
        ports = []
        ports.append(dst.port)
        network_info.update({dst.IP: ports})
    else:
        if dst.port not in result:
            result.append(dst.port)
            network_info.update({dst.IP: result})
    return


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
# open the original csv data file
flow_file = csv.reader(open(filepath, 'r'))

valid_IPs = ['192.168.100.2', '192.168.100.3', '192.168.100.4', '192.168.100.5', '192.168.100.6',
             '192.168.200.2', '192.168.200.3', '192.168.200.4', '192.168.200.5', '192.168.200.8', '192.168.200.9',
             '192.168.210.2', '192.168.210.3', '192.168.210.4', '192.168.210.5',
             '192.168.220.2', '192.168.220.3', '192.168.220.4', '192.168.220.5', '192.168.220.6', '192.168.220.7',
             '192.168.220.8', '192.168.220.9', '192.168.220.10', '192.168.220.11', '192.168.220.12', '192.168.220.13',
             '192.168.220.14', '192.168.220.15', '192.168.220.16',
             'DNS', 'EXT_SERVER']

flow_data = []
connections = []
network_events = []
srcIP_ratio = {}
network_info = {}

# record the above valid_IPs into network_info
for ip in valid_IPs:
    ports = []
    network_info.update({ip: ports})

theta0 = 0.8
theta1 = 0.2
eita0 = 0.01
eita1 = 99
start_bound = 0
end_bound = 20

timing = 0

isFirstrow = True
head = next(flow_file)
firstrow = next(flow_file)
start = get_time(firstrow[0])
window_index = 0

for row in flow_file:

    if isFirstrow:
        flow_data.append([])
        flow_data[window_index].append(firstrow)
        isFirstrow = False

    if row[13] == "dos":
        continue

    end = get_time(row[0])
    timeArray = time.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
    if timeArray.tm_hour == 6:
        pass
    if timeArray.tm_hour > timing:
        print(str(timeArray.tm_hour) + "o'clock")
        timing = timing + 1
    elif timeArray.tm_hour < start_bound:
        continue
    elif timeArray.tm_hour >= end_bound:
        # Calculate precision here.
        exit(0)

    # before add this row (which is a flow record) into each timewindow,
    # we need to use this row to update the Network_information, which is
    # recorded the information about the successful TCP connections and <ip,port>.
    update_network_info(row)
    update_network_info_for_failed_connection(row)

    flow_data[window_index].append(row)

    if end - start >= 60:
        generate_network_event(flow_data[window_index])
        start = end
        flow_data.append([])
        window_index = window_index + 1
