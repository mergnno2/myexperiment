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


def detect_scans(flows, diff_src):
    global activity_IDs
    count_d_a = 0
    count_d_n = 0

    diff_dst_ip = []
    diff_dst_pt = []

    i = 0
    while i < len(diff_src):
        for f in flows:
            if f[3] == diff_src[i] and re.search("S", f[10]) is not None:
                if f[5] not in diff_dst_ip:
                    diff_dst_ip.append(f[5])
                if f[6] not in diff_dst_pt:
                    diff_dst_pt.append(f[6])

        if len(diff_dst_ip) > MAX_IP_NUM or len(diff_dst_pt) > MAX_PT_NUM:
            # alarm diff_src[i] as a port scanner
            for f in flows:
                if f[3] == diff_src[i]:
                    if f[12] == "attacker":
                        count_d_a = count_d_a + 1
                        result = activity_IDs.get(f[14])
                        if result is None:
                            print("detected activity:", f[14], "at time:", flows[-1][0])
                            activity_IDs.update({f[14]: get_time(flows[-1][0])})
                    else:
                        count_d_n = count_d_n + 1
        diff_dst_ip.clear()
        diff_dst_pt.clear()
        i = i + 1

    return count_d_a, count_d_n


def get_diff_src(flows):
    diff = []

    for f in flows:
        if f[3] not in diff:
            diff.append(f[3])

    return diff


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
    # if timeArray.tm_hour >= 21:
    # return True
    return False


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-"
filepath_week_1 = "week1.csv"
filepath_week_2 = "week2.csv"
filepath_week_3 = "week3.csv"
filepath_week_4 = "week4.csv"
filepath_attack_log = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\attack_logs\\attack_logs_intern.csv"

# open the original csv data file
flow_file_week_1 = csv.reader(open(filepath + filepath_week_1, 'r'))
flow_file_week_2 = csv.reader(open(filepath + filepath_week_2, 'r'))
flow_file_week_3 = csv.reader(open(filepath + filepath_week_3, 'r'))
flow_file_week_4 = csv.reader(open(filepath + filepath_week_4, 'r'))
flow_files = [flow_file_week_1, flow_file_week_2, flow_file_week_3, flow_file_week_4]
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
time_window = 300
MAX_IP_NUM = 22
MAX_PT_NUM = 22

# counters for calculate the precision
count_total = 0
count_total_normal = 0
count_total_abnormal = 0
count_detected_abnormal = 0
count_detected_normal = 0
activity_IDs = {}  # record the activity ID that system detected
k = 0
while k < len(flow_files):
    attribute_line = next(flow_files[k])

    start_time = get_time(next(flow_files[k])[0])
    end_time = start_time
    for row in flow_files[k]:

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
        if end_time - start_time > time_window:
            # first, get the different source IP in per time window
            diff_src = get_diff_src(flows=flows_in_window)

            (cda, cdn) = detect_scans(flows=flows_in_window, diff_src=diff_src)
            count_detected_abnormal = count_detected_abnormal + cda
            count_detected_normal = count_detected_normal + cdn

            # step 4, update all the counters for calculate the TP and FP
            for f in flows_in_window:
                count_total = count_total + 1
                count_total_abnormal = count_total_abnormal + counter_for_abnormal(row_to_count_abnormal=f)
                count_total_normal = count_total_normal + counter_for_normal(row_to_count_normal=f)

            flows_in_window.clear()
            start_time = end_time
    k = k + 1

# step 5, once the program ends, we can calculate the precision of the algorithm
calculate_precision(count_total=count_total, count_total_abnormal=count_total_abnormal,
                    count_total_normal=count_total_normal, count_detected_abnormal=count_detected_abnormal,
                    count_detected_normal=count_detected_normal)
