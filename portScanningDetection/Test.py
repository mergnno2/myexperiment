# This version follows the detection rules:
# only consider TCP flows and filter out those flows without SYN flag.
# if a flow has SYN flag and don't have ACK flag, the source IP is considered as scanning attacker.
import re
import pandas as pd
import time
import numpy as np
import csv
import matplotlib.pyplot as plt
from matplotlib.pyplot import MultipleLocator


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
    global count_non_tcp_attacker
    if row_to_count_abnormal[12] == "attacker":
        if re.search("TCP", row_to_count_abnormal[2]) is None:
            count_non_tcp_attacker = count_non_tcp_attacker + 1
        return 1
    return 0


def counter_for_normal(row_to_count_normal):
    if row_to_count_normal[12] != "attacker":
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
    print("detected activity", len(activity_IDs), " IDs:", activity_IDs)
    print(count_non_tcp_attacker)
    return


def print_timing(row_to_print_time):
    global timing

    timeArray = time.strptime(row_to_print_time[0], "%Y-%m-%d %H:%M:%S.%f")

    if timing == 24 and timeArray.tm_hour == 0:
        timing = 0
    if timeArray.tm_hour >= timing:
        print("Month:", timeArray.tm_mon, "Day:", timeArray.tm_mday, ",", timing % 24, "o'clock")
        timing = timing + 1

    '''if timeArray.tm_mday < 23:
        continue
    if timeArray.tm_hour < 7:
        continue
    if timeArray.tm_hour <= 7 and timeArray.tm_min < 30:
        continue
    if timeArray.tm_hour == 14 and timeArray.tm_min > 35:
        break'''
    if timeArray.tm_hour >= 12:
        return True
    return False


filepath_week_1 = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
filepath_week_2 = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week2.csv"

# open the original csv data file
flow_file_week_1 = csv.reader(open(filepath_week_1, 'r'))
flow_file_week_2 = csv.reader(open(filepath_week_2, 'r'))
# write_file = csv.writer(open(filepath2, 'w', newline=""))

flows_in_window = []
timing = 0

count_total_attacker = 0
count_d_a = 0
count_non_tcp_attacker = 0

attribute_line = next(flow_file_week_1)
start_time = get_time(next(flow_file_week_1)[0])
end_time = start_time
for row in flow_file_week_1:

    # step 1, finish some filtering step
    if pre_operation(row_to_pre_operate=row):
        continue

    # step 2, print the timing information
    time_to_end = print_timing(row_to_print_time=row)
    if time_to_end:
        break
    flow = row

    flags = flow[10]
    proto = flow[2]
    type = flow[12]

    if type == "attacker":
        count_total_attacker = count_total_attacker + 1

    if re.search("TCP", proto) is None:
        if type == "attacker":
            count_non_tcp_attacker = count_non_tcp_attacker + 1
        continue
    if re.search("S", flags) is not None:
        if re.search("A", flags) is None:
            # this flow is a abnormal flow
            if type == "attacker":
                count_d_a = count_d_a + 1


print(count_total_attacker, count_d_a, count_non_tcp_attacker)
