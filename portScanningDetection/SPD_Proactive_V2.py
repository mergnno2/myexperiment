# This code refer to the paper "Detection of slow port scans in flow-based network traffic"
# The data set used by the above paper is also "CIDDS-001"
# Start date: 09.09.2021
import re
import pandas as pd
import time
import numpy as np
import csv


# import matplotlib.pyplot as plt


class Host(object):
    def __init__(self, IP):
        self.IP = IP
        self.flows = []
        self.diff_ports = []


def check_suspicious(flow):
    # check one flow if it is a suspicious flow by checking the flags

    # return types:
    # 0 - not suspicious
    # 1 - RST error
    # 2 - ICMP error
    if re.search('F', flow[10]) is not None:
        return 0
    elif re.search('S', flow[10]) is not None:
        return 0
    elif re.search('U', flow[10]) is not None:
        return 0
    elif re.search('P', flow[10]) is not None:
        return 0
    elif re.search('R', flow[10]) is not None:
        return 1
    elif re.search("3\.", flow[6]) is not None:
        return 2
    return 0


def detect_abnormal(flow):
    # count detected abnormal flows
    c_d_A = 0
    # count detected normal flows
    c_d_B = 0

    # the main process of the algorithm using dynamic time window
    suspicious_type = check_suspicious(flow=flow)
    if suspicious_type == 0:
        # it's not a suspicious flow
        return c_d_A, c_d_B
    else:
        IP = flow[5]
    # it is a suspicious flow, handle this flow by detection algorithm

    # first check if the hosts[] has already recorded the srcIP and suspicious type of this flow
    isNew = True
    i = 0
    while i < len(hosts):
        if hosts[i].IP == IP:
            current_host = hosts[i]
            isNew = False
            break
        i = i + 1

    if isNew:
        current_host = Host(IP=IP)
        current_host.flows.append(flow)
        current_host.diff_ports.append(flow[4])
        hosts.append(current_host)
        # and if it's the first abnormal flow of the given host, do nothing and waiting for second one.
        return c_d_A, c_d_B

    current_host.flows.append(flow)
    if flow[4] not in current_host.diff_ports:
        current_host.diff_ports.append(flow[4])

    # the host of this abnormal flow has already appears before, then run the algorithm
    if len(current_host.flows) >= 3 and len(current_host.diff_ports) >= 2:

        # it is considered as attacker

        for flow in current_host.flows:
            if flow[12] == "victim":
                c_d_A = c_d_A + 1
                # record the detected activity ID
                activity_result = activity_detected.get(flow[14])
                if activity_result is None:
                    print("detected activity:", flow[14], "at time:", current_host.flows[-1][0])
                    activity_detected.update({flow[14]: get_time(current_host.flows[-1][0])})
            else:
                c_d_B = c_d_B + 1

        current_host.flows.clear()
        current_host.diff_ports.clear()

    return c_d_A, c_d_B


def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp


def pre_operation(row_to_pre_operate):
    # skip the dos attack and brute force attack flows
    if row_to_pre_operate[13] == "dos" or row_to_pre_operate[13] == "bruteForce":
        return True
    return False


def counter_for_victim(row_to_count_victim):
    if row_to_count_victim[12] == "victim":
        return 1
    return 0


def counter_for_other(row_to_count_other):
    if row_to_count_other[12] != "victim":
        return 1
    return 0


def calculate_precision(count_total, count_total_victim, count_total_other,
                        count_detected_victim, count_detected_other):
    if count_total_victim == 0:
        count_total_victim = 1
    if count_total_other == 0:
        count_total_other = 1

    # calculate detection delay here
    delay = []
    detected_ids = activity_detected.keys()
    for id in detected_ids:
        activity_start_time = activity_total.get(id)
        activity_detect_time = activity_detected.get(id)
        delay.append(activity_detect_time - activity_start_time)
    delay_mean = 0
    for item in delay:
        delay_mean = delay_mean + item
    delay_mean = delay_mean / len(delay)

    TPR = count_detected_victim / count_total_victim
    FPR = count_detected_other / count_total_other
    print("count_detected_victim", count_detected_victim, "count_total_victim", count_total_victim, "TPR:", TPR)
    print("count_detected_other", count_detected_other, "count_total_other", count_total_other, "FPR:", FPR)
    print("count_total", count_total)
    print("detected activity", len(activity_detected), " IDs:", activity_detected.keys())
    print("detection delay mean:", delay_mean)
    return


def print_timing(row_to_print_time):
    global timing

    timeArray = time.strptime(row_to_print_time[0], "%Y-%m-%d %H:%M:%S.%f")

    if timing == 24 and timeArray.tm_hour == 0:
        timing = 0
    if timeArray.tm_hour >= timing:
        print("Month:", timeArray.tm_mon, "Day:", timeArray.tm_mday, ",", timing % 24, "o'clock")
        timing = timing + 1

    '''if timeArray.tm_mday < 16:
        return 1
    if timeArray.tm_hour < 13:
        return 1
    if timeArray.tm_min < 30:
        return 1
    if timeArray.tm_hour > 16 and timeArray.tm_min>30:
        return 2'''
    #if timeArray.tm_mday >= 17:
        #return 2
    return 0


attack_log_filepath = "D:/Python/Python37/myexperiment/portScanningDetection" + \
                      "/CIDDS-001/attack_logs/attack_logs_intern.csv"
filepath_basic = "D:/Python/Python37/myexperiment/portScanningDetection/CIDDS-001/traffic/OpenStack/"
filepath_subfiles = ["CIDDS-001-internal-week1.csv",
                     "CIDDS-001-internal-week2.csv",
                     "CIDDS-001-internal-week3.csv",
                     "CIDDS-001-internal-week4.csv"]
filepath_total = []

for subfile in filepath_subfiles:
    filepath_total.append(filepath_basic + subfile)

# open the original csv data file
attack_log_file = csv.reader(open(attack_log_filepath, 'r'))
flow_file = []
for file in filepath_total:
    flow_file.append(csv.reader(open(file, 'r')))
# write_file = csv.writer(open(filepath2, 'w', newline=""))

hosts = []  # record the hosts which is related to abnormal flows and ready to detected by the algorithm

timing = 0  # print time information

count_suspicious = 0
count_victim_suspicious = 0
count_victim_normal = 0

# counters for calculate the precision
count_total = 0
count_total_other = 0
count_total_victim = 0
count_detected_victim = 0
count_detected_other = 0
activity_total = {}  # record the total scan activities
activity_detected = {}  # record the activities that system detected and also record the time

attribute_line = next(attack_log_file)
for log in attack_log_file:
    if re.search("nmap", log[7]) is not None:
        activity_id = log[5]
    else:
        continue

    if activity_id == '1':
        start_time = 1489507276.0  # the first attack start at 3.15.00:00
    else:
        start_time = float(get_time(log[1]))
    activity_total.update({activity_id: start_time})

file_index = 0
while file_index < len(flow_file):
    attribute_line = next(flow_file[file_index])
    for row in flow_file[file_index]:
        # step 1, finish some filtering step
        if pre_operation(row_to_pre_operate=row):
            continue

        # step 2, print the timing information
        time_to_end = print_timing(row_to_print_time=row)
        if time_to_end == 1:
            continue
        elif time_to_end == 2:
            break

        if check_suspicious(row) != 0:
            count_suspicious = count_suspicious + 1
            count_victim_suspicious = count_victim_suspicious + counter_for_victim(row_to_count_victim=row)
        else:
            count_victim_normal = count_victim_normal + counter_for_victim(row_to_count_victim=row)
        # step 3
        # then testify each flow(row) if its ICMP error or a TCP-RST package
        # then run the abnormal detection algorithm using dynamic time window
        (count_A, count_B) = detect_abnormal(flow=row)
        # count_A refers to the flows that victim sent.
        # count_B refers to the flows that sent by someone who is not victim
        # (maybe normal host or attacker, but not victim).

        # step 4, update all the counters for calculate the TP and FP
        count_total = count_total + 1
        count_total_victim = count_total_victim + counter_for_victim(row_to_count_victim=row)
        count_total_other = count_total_other + counter_for_other(row_to_count_other=row)
        count_detected_victim = count_detected_victim + count_A
        count_detected_other = count_detected_other + count_B
    file_index = file_index + 1

# step 5, once the program ends, we can calculate the precision of the algorithm
calculate_precision(count_total=count_total, count_total_victim=count_total_victim,
                    count_total_other=count_total_other, count_detected_victim=count_detected_victim,
                    count_detected_other=count_detected_other)
print(count_suspicious, count_victim_suspicious, count_victim_normal)
