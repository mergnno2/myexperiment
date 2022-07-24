# This code refer to the paper "Detection of slow port scans in flow-based network traffic"
# The data set used by the above paper is also "CIDDS-001"
# Start date: 09.09.2021
import re
import pandas as pd
import time
import numpy as np
import csv
import matplotlib.pyplot as plt
from matplotlib.pyplot import MultipleLocator


class Flow(object):
    def __init__(self, sip, spt, dip, dpt, time_stamp, flag_sum_1, type_1, activity_id_1, type_2="",
                 activity_id_2="", flag_sum_2="", success=False):
        self.sip = sip
        self.spt = spt
        self.dip = dip
        self.dpt = dpt
        self.time_stamp = time_stamp

        # direction 1 means sip to dip, while direction 2 means dip to sip
        self.flag_sum_1 = flag_sum_1
        self.flag_sum_2 = flag_sum_2

        # type_1 is the attack type of direction 1
        self.type_1 = type_1
        self.type_2 = type_2

        self.activity_id_1 = activity_id_1
        self.activity_id_2 = activity_id_2

        self.success = success


def check_flow(flow):
    # this is the main method of detection

    global flows, activity_IDs, timer
    count_d_a = 0
    count_d_n = 0
    proto = flow[2]
    sip = flow[3]
    spt = flow[4]
    dip = flow[5]
    dpt = flow[6]
    time_stamp = get_time(flow[0])
    id_1 = [sip, spt, dip, dpt]
    id_2 = [dip, dpt, sip, spt]
    flags = flow[10]
    type = flow[12]  # type is used to calculate the TPR and FPR
    activity_id = flow[14]

    # if this is not TCP flows, return
    if re.search("TCP", proto) is None:
        return count_d_a, count_d_n

    # find the specific flow that matches id_1 or id_2
    id_type = 0
    i = 0
    while i < len(flows):
        if [flows[i].sip, flows[i].spt, flows[i].dip, flows[i].dpt] == id_1:
            id_type = 1
            break
        elif [flows[i].sip, flows[i].spt, flows[i].dip, flows[i].dpt] == id_2:
            id_type = 2
            break
        i = i + 1

    if id_type == 0:
        # if no result, it means that this is a new connection attempt
        # generate a new Flow() using flag_sum_1 direction
        flows.append(Flow(sip=sip, spt=spt, dip=dip, dpt=dpt, time_stamp=time_stamp, flag_sum_1=flags, type_1=type,
                          activity_id_1=activity_id))
        return count_d_a, count_d_n

    if flows[i].success:
        # this connection is a success one, just update the time_stamp
        flows[i].time_stamp = time_stamp
        return count_d_a, count_d_n

    # else, this TCP connection is not succeed yet, check the three-way handshake
    if id_type == 1:
        # if id_1 is found, update the TCP flag_sum_1 and time_stamp
        flows[i].flag_sum_1 = flags
        flows[i].time_stamp = time_stamp

    if id_type == 2:
        # if id_2 is found, check the time_stamp
        if time_stamp - flows[i].time_stamp > 120:
            # if time out, delete the old information and generate a new Flow() item using flag_sum_1 direction
            flows.__delitem__(i)
            flows.append(Flow(sip=sip, spt=spt, dip=dip, dpt=dpt, time_stamp=time_stamp, flag_sum_1=flags, type_1=type,
                              activity_id_1=activity_id))
        else:
            # if not time out, then check the flag_sum of two directions
            # first update the flags of direction 2
            flows[i].flag_sum_2 = flags
            flows[i].type_2 = type
            flows[i].activity_id_2 = activity_id

            # during the three-way handshake, one must send ACK flag
            if re.search("A", flows[i].flag_sum_1) is None:
                # direction 1 is not good
                # dip is scanner
                # update the two counters according to the type of current abnormal flow
                if flows[i].type_1 == "attacker":
                    count_d_a = count_d_a + 1
                    # update the activity ID that system detected
                    if flows[i].activity_id_1 not in activity_IDs:
                        print("detected activity:", flows[i].activity_id_1, "at time:", timer)
                        activity_IDs.append(flows[i].activity_id_1)
                else:
                    count_d_n = count_d_n + 1
            elif re.search("S", flows[i].flag_sum_1) is None and re.search("R", flows[i].flag_sum_1) is None:
                # direction 1 is not good
                # dip is scanner
                # update the two counters according to the type of current abnormal flow
                if flows[i].type_1 == "attacker":
                    count_d_a = count_d_a + 1
                    # update the activity ID that system detected
                    if flows[i].activity_id_1 not in activity_IDs:
                        print("detected activity:", flows[i].activity_id_1, "at time:", timer)
                        activity_IDs.append(flows[i].activity_id_1)
                else:
                    count_d_n = count_d_n + 1

            elif re.search("A", flows[i].flag_sum_2) is None:
                # direction 2 is not good
                # sip is scanner
                # update the two counters according to the type of current abnormal flow
                if flows[i].type_2 == "attacker":
                    count_d_a = count_d_a + 1
                    # update the activity ID that system detected
                    if flows[i].activity_id_2 not in activity_IDs:
                        print("detected activity:", flows[i].activity_id_2, "at time:", timer)
                        activity_IDs.append(flows[i].activity_id_2)
                else:
                    count_d_n = count_d_n + 1
            elif re.search("S", flows[i].flag_sum_2) is None and re.search("R", flows[i].flag_sum_2) is None:
                # direction 2 is not good
                # sip is scanner
                # update the two counters according to the type of current abnormal flow
                if flows[i].type_2 == "attacker":
                    count_d_a = count_d_a + 1
                    # update the activity ID that system detected
                    if flows[i].activity_id_2 not in activity_IDs:
                        print("detected activity:", flows[i].activity_id_2, "at time:", timer)
                        activity_IDs.append(flows[i].activity_id_2)
                else:
                    count_d_n = count_d_n + 1
            else:
                # this is a good three-way handshake
                # both two directions includes the ACK and TCP flags, update as a success connection
                flows[i].success = True

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
    TPR = count_detected_abnormal / count_total_abnormal
    FPR = count_detected_normal / count_total_normal
    print("count_detected_abnormal", count_detected_abnormal, "count_total_abnormal", count_total_abnormal, "TPR:", TPR)
    print("count_detected_normal", count_detected_normal, "count_total_normal", count_total_normal, "FPR:", FPR)
    print("count_total", count_total)
    print("detected activity", len(activity_IDs), " IDs:", activity_IDs)
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
    if timeArray.tm_hour >= 5:
        return True
    return False


filepath_week_1 = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
filepath_week_2 = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week2.csv"

# open the original csv data file
flow_file_week_1 = csv.reader(open(filepath_week_1, 'r'))
flow_file_week_2 = csv.reader(open(filepath_week_2, 'r'))
# write_file = csv.writer(open(filepath2, 'w', newline=""))

hosts = []  # record the hosts which is related to abnormal flows and ready to detected by the algorithm
flows = []
flows_in_window = []
timing = 0
# timer is used print the detection time
timer = 0

# counters for calculate the precision
count_total = 0
count_total_normal = 0
count_total_abnormal = 0
count_detected_abnormal = 0
count_detected_normal = 0
activity_IDs = []  # record the activity ID that system detected

attribute_line = next(flow_file_week_1)
start_time = get_time(next(flow_file_week_1)[0])
end_time = start_time
for row in flow_file_week_1:
    timer = row[0]

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
