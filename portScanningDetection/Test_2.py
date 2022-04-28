# this file aims to test the EWMA algorithm using simple sequence of digital number.
import random
import re

import matplotlib.pyplot as plt
import csv
import time



def vertical_operate(timewindow, group_vertical):
    c_d_n = 0
    c_d_a = 0

    for connection in group_vertical:
        connection.shown_in_current_window = False
        connection.dpt_updated = False
        connection.dpti.clear()
        connection.flush_flows.clear()

    # first mark the connection in current window
    for flow in timewindow:
        j = 0
        isNew = True
        while j < len(group_vertical):
            if group_vertical[j].match(sip=flow[3], dip=flow[5]):
                if group_vertical[j].shown_in_current_window is False:
                    group_vertical[j].continual_count = group_vertical[j].continual_count + 1
                group_vertical[j].shown_in_current_window = True
                group_vertical[j].dpti.append(flow[5])
                group_vertical[j].attached_flows.append(flow)
                group_vertical[j].flush_flows.append(flow)
                isNew = False
            j = j + 1
        if isNew:
            group_vertical.append(Vertical(sip=flow[3], dip=flow[5], dpt=flow[6], flow=flow))

    # second delete the connection which didn't appear in current window and continual count is less than 5
    i = 0
    while i < len(group_vertical):
        if group_vertical[i].shown_in_current_window is True:
            # current sip-dpt connection apears in current time window
            if group_vertical[i].continual_count == 1:
                for pt in group_vertical[i].dpti:
                    group_vertical[i].pre_dpt.append(pt)
            else:
                # check if there is new dip for current sip-dpt connection
                dpt_updated = False
                for dpt in group_horizontal[i].dpti:
                    if dpt not in group_vertical[i].pre_dpt:
                        dpt_updated = True
                if dpt_updated is False:
                    if group_vertical[i].continual_count <= 5:
                        group_vertical.__delitem__(i)
                        continue
                    else:
                        # time to calulate the entropy
                        if calculateEntropy_vertical(list_dpt=group_vertical[i].pre_dpt):
                            # it is an abnormal connection that entropy exceed the threshold.
                            for flow in group_vertical[i].attached_flows:
                                if flow[12] == "attacker":
                                    k = 0
                                    while k < len(timewindow):
                                        if len(timewindow[k]) == 16:
                                            if timewindow[k] == flow:
                                                timewindow[k].append("detected_abnormal")
                                                c_d_a = c_d_a + 1
                                        k = k + 1
                                else:
                                    k = 0
                                    while k < len(timewindow):
                                        if len(timewindow[k]) == 16:
                                            if timewindow[k] == flow:
                                                timewindow[k].append("detected_normal")
                                                c_d_n = c_d_n + 1
                                        k = k + 1
                        else:
                            group_vertical[i].pre_dpt.clear()
                            for pt in group_vertical[i].dpti:
                                group_vertical[i].pre_dpt.append(pt)
                            group_vertical[i].pre_dpt = group_vertical[i].dpti
                            group_vertical[i].attached_flows = group_vertical[i].flush_flows
                            group_vertical[i].flush_flows.clear()
                            group_vertical[i].continual_count = 1
                else:
                    # set the pre_dip
                    u_dpt = group_vertical[i].pre_dpt + group_vertical[i].dpti
                    group_vertical[i].pre_dpt = u_dpt
        elif group_vertical[i].shown_in_current_window is False:
            # current sip-dpt connection did not apears in current time window
            if group_vertical[i].continual_count <= 5:
                # It cannot meet the sustainability characteristics
                group_vertical.__delitem__(i)
                continue
            else:
                # time to calulate the entropy
                if calculateEntropy_vertical(list_dpt=group_vertical[i].pre_dpt):
                    # it is an abnormal connection that entropy exceed the threshold.
                    for flow in group_vertical[i].attached_flows:
                        if flow[12] == "attacker":
                            k = 0
                            while k < len(timewindow):
                                if len(timewindow[k]) == 16:
                                    if timewindow[k] == flow:
                                        timewindow[k].append("detected_abnormal")
                                        c_d_a = c_d_a + 1
                                k = k + 1
                        else:
                            k = 0
                            while k < len(timewindow):
                                if len(timewindow[k]) == 16:
                                    if timewindow[k] == flow:
                                        timewindow[k].append("detected_normal")
                                        c_d_n = c_d_n + 1
                                k = k + 1
                group_vertical.__delitem__(i)
                continue
        i = i + 1

    return c_d_n, c_d_a

def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp


def pre_operation(row):
    # skip the dos attack and brute force attack flows
    if row[13] == "dos" or row[13] == "bruteForce":
        return True
    return False


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
flow_file = csv.reader(open(filepath, 'r'))
filepath_write = "D:\Python\Python37\myexperiment\only-67-68.csv"
flow_file_write = csv.writer(open(filepath_write, 'w', newline=""))

flow_data = []

timing = 0

stamps = []
ewma = []
per = []
alpha = 0.01
end = 0
start = 0
sum = 0
head = next(flow_file)
first_line = next(flow_file)

for row in flow_file:
    print(row)
    flow_data.append(row)
    per.append(row)
    if pre_operation(row=row) is True:
        continue

    timeArray = time.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
    if timing == 24 and timeArray.tm_hour == 0:
        timing = 0
    if timeArray.tm_hour >= timing:
        print("Month:", timeArray.tm_mon, "Day:", timeArray.tm_mday, ",", timing % 24, "o'clock")
        timing = timing + 1
    if timeArray.tm_hour>=3:
        break
if per[3] == flow_data[3]:
    print("temp")