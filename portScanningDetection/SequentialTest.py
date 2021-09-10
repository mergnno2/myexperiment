# This code refer to the paper "Detection of slow port scans in flow-based network traffic"
# The data set used by the above paper is also "CIDDS-001"
# Start date: 09.09.2021

import pandas as pd
import time
import numpy as np
import csv

class Host(object):
    def __init__(self,IP):
        self.IP=IP
        self.opening_ports=[]

class Network_Event(object):
    def __init__(self,IP):
        self.IP=IP
        self.ICMP=0
        self.RST=0
        self.RwA=0
        self.NeIP=0
        self.NeTCP=0
    def calculate_attribute(self,timewindow):
        ICMP = RST = RwA = NeIP = NeTCP = 0

        self.ICMP=ICMP
        self.RST=RST
        self.RwA=RwA
        self.NeIP=NeIP
        self.NeTCP=NeTCP

def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp

def check_IP(IP):
    for event in network_events:
        if event.IP == IP:
            return False
    return True

def generate_network_event(time_window):
    network_events.clear()

    isNewIP = False
    for eachflow in time_window:
        IP = eachflow[3]
        isNewIP = check_IP(IP)
        if isNewIP:
            event = Network_Event(IP)
            isNewIP = False
        else:
            pass

    return
information_path = "D:\Python\Python37\myexperiment\portScanningDetection\\Network_Information.csv"
filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
# open the original csv data file
info = csv.reader(open(information_path, 'r'))
file = csv.reader(open(filepath, 'r'))

network_info = {}
network_events = []
flow_data = []
start_bound = 0
end_bound = 9

timing = 0

isFirstrow = True
head = next(file)
firstrow = next(file)
start = get_time(firstrow[0])
window_index=0


for row in info:
    i = 1
    value = []
    while i <len(row):
        value.append(row[i])
        i = i + 1
    item = {row[0]:value}
    network_info.update(item)
print("hello")

for row in file:

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

