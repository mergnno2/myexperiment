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


def check_flow(flow):
    global flows_in_window, activity_IDs
    count_d_a = 0
    count_d_n = 0
    flags = flow[10]
    proto = flow[2]
    type = flow[12]
    if re.search("TCP", proto) is None:
        return count_d_a, count_d_n
    if re.search("S", flags) is not None:
        if re.search("A", flags) is None:
            # this flow is a abnormal flow
            if type == "attacker":
                count_d_a = count_d_a + 1
                result = activity_IDs.get(flow[14])
                if result is None:
                    print("detected activity:", flow[14], "at time:", flows_in_window[-1][0])
                    activity_IDs.update({flow[14]: get_time(flows_in_window[-1][0])})
            else:
                count_d_n = count_d_n + 1
    return count_d_a, count_d_n


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
    if row_to_count_abnormal[12] == "attacker":
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
    detection_delay_mean = 0
    keys = activity_IDs
    for k in keys:
        value = activities.get(k)
        detect_time = activity_IDs.get(k)
        detection_delay_mean = detection_delay_mean + float(detect_time) - float(value)
    detection_delay_mean = detection_delay_mean / len(activity_IDs.keys())
    TPR = count_detected_abnormal / count_total_abnormal
    FPR = count_detected_normal / count_total_normal
    print("count_detected_abnormal", count_detected_abnormal, "count_total_abnormal", count_total_abnormal, "TPR:", TPR)
    print("count_detected_normal", count_detected_normal, "count_total_normal", count_total_normal, "FPR:", FPR)
    print("count_total", count_total)
    print("detected activity", len(activity_IDs.keys()), " IDs:", activity_IDs.keys())
    print("detection delay:", detection_delay_mean)
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
    #if timeArray.tm_hour >= 12:
        #return True
    return False


filepath_week_1 = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
filepath_week_2 = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week2.csv"
filepath_attack_log = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\attack_logs\\attack_logs_intern.csv"

# open the original csv data file
flow_file_week_1 = csv.reader(open(filepath_week_1, 'r'))
flow_file_week_2 = csv.reader(open(filepath_week_2, 'r'))
log_file = csv.reader(open(filepath_attack_log, 'r'))
# write_file = csv.writer(open(filepath2, 'w', newline=""))
attribute_line = next(log_file)
activities = {}

for row in log_file:
    if row[5] == "1":
        activities.update({row[5]: 1489507276.0})
        continue
    activities.update({row[5]: get_time(row[1])})

flows_in_window = []
timing = 0

# counters for calculate the precision
count_total = 0
count_total_normal = 0
count_total_abnormal = 0
count_detected_abnormal = 0
count_detected_normal = 0
activity_IDs = {}  # record the activity ID that system detected

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

    flows_in_window.append(row)
    end_time = get_time(row[0])
    # step 3
    if end_time - start_time > 20:
        for f in flows_in_window:
            (count_a, count_n) = check_flow(flow=f)

            # step 4, update all the counters for calculate the TP and FP
            count_total = count_total + 1
            count_total_abnormal = count_total_abnormal + counter_for_abnormal(row_to_count_abnormal=f)
            count_total_normal = count_total_normal + counter_for_normal(row_to_count_normal=f)
            count_detected_abnormal = count_detected_abnormal + count_a
            count_detected_normal = count_detected_normal + count_n

        flows_in_window.clear()
        start_time = end_time

attribute_line = next(flow_file_week_2)
for row in flow_file_week_2:
    # step 1, finish some filtering step
    if pre_operation(row_to_pre_operate=row):
        continue

    # step 2, print the timing information
    time_to_end = print_timing(row_to_print_time=row)
    if time_to_end:
        break

    flows_in_window.append(row)
    end_time = get_time(row[0])
    # step 3
    if end_time - start_time > 20:
        for f in flows_in_window:
            (count_a, count_n) = check_flow(flow=f)

            # step 4, update all the counters for calculate the TP and FP
            count_total = count_total + 1
            count_total_abnormal = count_total_abnormal + counter_for_abnormal(row_to_count_abnormal=f)
            count_total_normal = count_total_normal + counter_for_normal(row_to_count_normal=f)
            count_detected_abnormal = count_detected_abnormal + count_a
            count_detected_normal = count_detected_normal + count_n

        flows_in_window.clear()
        start_time = end_time

# step 5, once the program ends, we can calculate the precision of the algorithm
calculate_precision(count_total=count_total, count_total_abnormal=count_total_abnormal,
                    count_total_normal=count_total_normal, count_detected_abnormal=count_detected_abnormal,
                    count_detected_normal=count_detected_normal)
