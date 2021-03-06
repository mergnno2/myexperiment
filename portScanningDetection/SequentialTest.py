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

    return NeIP


def count_NeTCP(srcIP, time_window):
    NeTCP = 0

    return NeTCP


def hosts_per_window(time_window):
    hosts = []
    for flow in time_window:
        if flow[3] not in hosts:
            hosts.append(flow[3])
    return hosts


def generate_network_event(time_window):
    ICMP = RST = RwA = NeIP = NeTCP = 0
    network_events.clear()
    hosts = hosts_per_window(time_window=time_window)
    for host in hosts:
        ICMP = count_ICMP(srcIP=host, time_window=time_window)
        RST = count_RST(srcIP=host, time_window=time_window)
        RwA = count_RwA(srcIP=host, time_window=time_window)
        NeIP = count_NeIP(srcIP=host, time_window=time_window)
        NeTCP = count_NeTCP(srcIP=host, time_window=time_window)
        network_events.append(Network_Event(IP=host, ICMP=ICMP, RST=RST, RwA=RwA, NeIP=NeIP, NeTCP=NeTCP))
    return


network_information_path = "D:\Python\Python37\myexperiment\portScanningDetection\\Network_Information.csv"
filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
# open the original csv data file
info_file = csv.reader(open(network_information_path, 'r'))
flow_file = csv.reader(open(filepath, 'r'))

network_info = {}
network_events = []
flow_data = []
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
