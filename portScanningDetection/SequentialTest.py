# This code refer to the paper "Detection of slow port scans in flow-based network traffic"
# The data set used by the above paper is also "CIDDS-001"
# Start date: 09.09.2021
import re
import pandas as pd
import time
import numpy as np
import csv


class Target(object):
    def __init__(self, IP, port):
        self.IP = IP
        self.port = port


class Host(object):
    def __init__(self, IP):
        self.IP = IP
        self.ports = []


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
        if flow[2] == "ICMP":  # 不考虑ICMP报文的“是否响应”特点
            continue
        if re.search("\.", flow[5]) != None:
            dstIP = flow[5][0:3]
            if flow[3] == srcIP:
                if int(dstIP) >= 224 and int(dstIP) <= 239:
                    continue
                if srcIP == "255.255.255.255":
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
        if flow[3] == srcIP and flow[5] not in diff_IP:
            diff_IP.append(flow[5])
    for ip in diff_IP:
        if network_info.get(ip) == None:
            NeIP = NeIP + 1
    return NeIP


def count_NeTCP(srcIP, time_window):
    NeTCP = 0
    diff_target = []
    for flow in time_window:
        if flow[2] == "ICMP":  # Without considering ICMP packet.
            continue
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
        srcIP_ratio.update({ip: 1.0})
    ratio = srcIP_ratio.get(ip)
    ai = event.ICMP + event.NeIP + event.NeTCP
    if ai > 0:
        ratio = ratio * ai * ((1 - theta1) / (1 - theta0))
    else:
        ratio = ratio * (theta1 / theta0)
    srcIP_ratio[ip] = ratio
    return


def detect_abnormal(event):
    if srcIP_ratio.get(event.IP) == None:
        return
    else:
        if srcIP_ratio.get(event.IP) > eita1:
            print("abnormal caused by the host:" + event.IP)
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
        RST = count_RST(srcIP=host, time_window=time_window)
        RwA = count_RwA(srcIP=host, time_window=time_window)
        NeIP = count_NeIP(srcIP=host, time_window=time_window)
        NeTCP = count_NeTCP(srcIP=host, time_window=time_window)
        network_events.append(Network_Event(IP=host, ICMP=ICMP, RST=RST, RwA=RwA, NeIP=NeIP, NeTCP=NeTCP))
        # One network event that is related to the 'host' is well generated from the given time window.
        # Update the corresponding srcIP's ratio according to the current network event attributes.
        update_ratio(event=network_events[-1])
        detect_abnormal(event=network_events[-1])
    return


network_information_path = "D:\Python\Python37\myexperiment\portScanningDetection\\Network_Information.csv"
filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
# open the original csv data file
info_file = csv.reader(open(network_information_path, 'r'))
flow_file = csv.reader(open(filepath, 'r'))

srcIP_ratio = {}
network_info = {}
network_events = []
flow_data = []
theta0 = 0.8
theta1 = 0.2
eita0 = 0.01
eita1 = 99
start_bound = 0
end_bound = 9

timing = 0

isFirstrow = True
head = next(flow_file)
firstrow = next(flow_file)
start = get_time(firstrow[0])
window_index = 0

for row in info_file:
    i = 1
    value = []
    while i < len(row):
        value.append(row[i])
        i = i + 1
    info_item = {row[0]: value}
    network_info.update(info_item)

for row in flow_file:

    if isFirstrow:
        flow_data.append([])
        flow_data[window_index].append(firstrow)
        isFirstrow = False

    end = get_time(row[0])
    timeArray = time.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
    if timeArray.tm_hour > timing:
        print(str(timeArray.tm_hour) + "o'clock")
        timing = timing + 1
    elif timeArray.tm_hour < start_bound:
        continue
    elif timeArray.tm_hour >= end_bound:
        # Calculate precision here.
        exit(0)

    flow_data[window_index].append(row)

    if end - start >= 60:
        generate_network_event(flow_data[window_index])
        start = end
        flow_data.append([])
        window_index = window_index + 1
