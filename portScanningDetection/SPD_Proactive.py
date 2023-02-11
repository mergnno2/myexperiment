# This code is the final version of method that I proposed in the thesis.
import re
import pandas as pd
import time
import numpy as np
import csv
import matplotlib.pyplot as plt
from matplotlib.pyplot import MultipleLocator


# import matplotlib.pyplot as plt


class Host(object):
    def __init__(self, IP):
        self.IP = IP
        self.rcvd_suspicious_count = 0
        self.rcvd_diff_ports = []


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
    elif re.search('P', flow[10]) is not None:
        return 0
    elif re.search('R', flow[10]) is not None:
        return 1
    elif re.search("3\.", flow[6]) is not None:
        return 2
    return 0


def detect_abnormal(flow):
    # count detected abnormal flows
    c_d_a = 0
    # count detected normal flows
    c_d_n = 0

    # the main process of the algorithm using dynamic time window
    # suspicious type is used to identify different scanning activities
    suspicious_type = check_suspicious(flow=flow)
    if suspicious_type == 0:
        # it's not a suspicious flow
        return
    else:
        # we don't care if it is 1 or 2 type
        IP = flow[5]
    # it is a suspicious flow, handle this flow by detection algorithm

    # first check if the hosts[] has already recorded the srcIP and suspicious type of this flow
    isNew = True
    i = 0
    while i < len(hosts):
        if hosts[i].IP == IP:
            current_host = hosts[i]
            isNew = False
        i = i + 1

    if isNew:
        current_host = Host(IP=IP)
        current_host.rcvd_suspicious_count = 1
        current_host.rcvd_diff_ports.append(flow[4])
        hosts.append(current_host)
        # and if it's the first abnormal flow of the given host, do nothing and waiting for second one.
        return

    current_host.rcvd_suspicious_count = current_host.rcvd_suspicious_count + 1
    # the host of this abnormal flow has already appears before, then run the algorithm
    if current_host.rcvd_suspicious_count >= 3 and len(current_host.rcvd_diff_ports) >= 2:

        # it is considered as attacker
        if current_host.IP == "192.168.220.16" or current_host.IP == "192.168.220.15":
            c_d_a = c_d_a + current_host.rcvd_suspicious_count
        else:
            c_d_n = c_d_n + current_host.rcvd_suspicious_count

        print("&&&&&&&&&  Scanning Activity Detected!  &&&&&&&&&", str(current_host.IP))
        # it is an abnormal host, we have made decision.

        current_host.rcvd_suspicious_count = 0
        current_host.rcvd_diff_ports.clear()

    return c_d_a, c_d_n


def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp


def pre_operation(row_to_pre_operate):
    # skip the dos attack and brute force attack flows
    if row_to_pre_operate[13] == "dos" or row_to_pre_operate[13] == "bruteForce":
        return True
    return False


def counter_for_abnormal(row_to_count_abnormal):
    if re.search('R', row_to_count_abnormal[10]) is not None and row_to_count_abnormal[12] == "victim":
        return 1
    elif re.search("ICMP", row_to_count_abnormal[2]) is not None and row_to_count_abnormal[12] == "victim":
        return 1
    return 0


def counter_for_normal(row_to_count_normal):
    if row_to_count_normal[12] == "normal":
        return 1
    return 0


def calculate_precision(count_total, count_total_abnormal, count_total_normal,
                        count_detected_abnormal, count_detected_normal):
    if count_total_abnormal == 0:
        count_total_abnormal = 1
    if count_total_normal == 0:
        count_total_normal = 1
    TPR = count_detected_abnormal / count_total_abnormal
    FPR = count_detected_normal / count_total_normal
    print("count_detected_abnormal", count_detected_abnormal, "count_total_abnormal", count_total_abnormal, "TPR:", TPR)
    print("count_detected_normal", count_detected_normal, "count_total_normal", count_total_normal, "FPR:", FPR)
    print("count_total", count_total)
    print("detected activities:", len(activity_ID), " IDs:", activity_ID)
    return


def print_timing(row_to_print_time):
    global timing

    timeArray = time.strptime(row_to_print_time[0], "%Y-%m-%d %H:%M:%S.%f")

    if timing == 24 and timeArray.tm_hour == 0:
        timing = 0
    if timeArray.tm_hour >= timing:
        print("Month:", timeArray.tm_mon, "Day:", timeArray.tm_mday, ",", timing % 24, "o'clock")
        timing = timing + 1

    if timeArray.tm_mday == 17:
        return True

    return False


filepath_week_1 = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
filepath_week_2 = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week2.csv"

# open the original csv data file
flow_file_week_1 = csv.reader(open(filepath_week_1, 'r'))
flow_file_week_2 = csv.reader(open(filepath_week_2, 'r'))
# write_file = csv.writer(open(filepath2, 'w', newline=""))

hosts = []  # record the hosts which is related to abnormal flows and ready to detected by the algorithm

timing = 0

# counters for calculate the precision
count_total = 0
count_total_normal = 0
count_total_abnormal = 0
count_detected_abnormal = 0
count_detected_normal = 0
activity_ID = []  # record the activity ID that system detected

attribute_line = next(flow_file_week_1)
for row in flow_file_week_1:

    # step 1, finish some filtering step
    if pre_operation(row_to_pre_operate=row):
        continue

    # step 2, print the timing information
    time_to_end = print_timing(row_to_print_time=row)
    if time_to_end:
        break

    # step 3
    # then testify each flow(row) if its ICMP error or a TCP-RST package
    # then run the abnormal detection algorithm using dynamic time window
    (count_a, count_n) = detect_abnormal(flow=row)

    # step 4, update all the counters for calculate the TP and FP
    count_total = count_total + 1
    count_total_abnormal = count_total_abnormal + counter_for_abnormal(row_to_count_abnormal=row)
    count_total_normal = count_total_normal + counter_for_normal(row_to_count_normal=row)
    count_detected_abnormal = count_detected_abnormal + count_a
    count_detected_normal = count_detected_normal + count_n

# repeat the above steps in week 2
attribute_line = next(flow_file_week_2)

for row in flow_file_week_2:

    # step 1, finish some filtering step
    if pre_operation(row_to_pre_operate=row):
        continue

    # step 2, print the timing information
    time_to_end = print_timing(row_to_print_time=row)
    if time_to_end:
        break

    # step 3
    # then testify each flow(row) if its ICMP error or a TCP-RST package
    # then run the abnormal detection algorithm using dynamic time window
    (count_a, count_n) = detect_abnormal(flow=row)

    # step 4, update all the counters for calculate the TP and FP
    count_total = count_total + 1
    count_total_abnormal = count_total_abnormal + counter_for_abnormal(row_to_count_abnormal=row)
    count_total_normal = count_total_normal + counter_for_normal(row_to_count_normal=row)
    count_detected_abnormal = count_detected_abnormal + count_a
    count_detected_normal = count_detected_normal + count_n

# step 5, once the program ends, we can calculate the precision of the algorithm
calculate_precision(count_total=count_total, count_total_abnormal=count_total_abnormal,
                    count_total_normal=count_total_normal, count_detected_abnormal=count_detected_abnormal,
                    count_detected_normal=count_detected_normal)
