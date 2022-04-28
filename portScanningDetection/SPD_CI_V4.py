import re

import pandas as pd
import time
import numpy as np
import csv


class Horizontal(object):
    def __init__(self, sip, dpt, dip, flow):
        self.sip = sip
        self.dpt = dpt
        self.dipi = []
        self.dipi.append(dip)
        self.pre_dip = []
        self.shown_in_current_window = True
        self.dip_updated = True
        self.continual_count = 1
        self.attached_flows = []
        self.attached_flows.append(flow)
        self.flush_flows = []
        self.flush_flows.append(flow)
        return

    def match(self, sip, dpt):
        if self.sip == sip and self.dpt == dpt:
            return True
        return False


class Vertical(object):
    def __init__(self, sip, dpt, dip, flow):
        self.sip = sip
        self.dip = dip
        self.dpti = []
        self.dpti.append(dpt)
        self.pre_dpt = []
        self.shown_in_current_window = True
        self.dpt_updated = True
        self.continual_count = 1
        self.attached_flows = []
        self.attached_flows.append(flow)
        self.flush_flows = []
        self.flush_flows.append(flow)
        return

    def match(self, sip, dip):
        if self.sip == sip and self.dip == dip:
            return True
        return False


def horizontal_operate(timewindow, group_horizontal):

    global detected_flows

    for connection in group_horizontal:
        connection.shown_in_current_window = False
        connection.dip_updated = False
        connection.dipi.clear()
        connection.flush_flows.clear()

    # first mark the connection in current window
    for flow in timewindow:
        j = 0
        isNew = True
        while j < len(group_horizontal):
            if group_horizontal[j].match(sip=flow[3], dpt=flow[6]):
                if group_horizontal[j].shown_in_current_window is False:
                    group_horizontal[j].continual_count = group_horizontal[j].continual_count + 1
                group_horizontal[j].shown_in_current_window = True
                group_horizontal[j].dipi.append(flow[5])
                group_horizontal[j].attached_flows.append(flow)
                group_horizontal[j].flush_flows.append(flow)
                isNew = False
            j = j + 1
        if isNew:
            group_horizontal.append(Horizontal(sip=flow[3], dip=flow[5], dpt=flow[6], flow=flow))

    # second delete the connection which didn't appear in current window and continual count is less than 5
    i = 0
    while i < len(group_horizontal):
        if group_horizontal[i].shown_in_current_window is True:
            # current sip-dpt connection apears in current time window
            if group_horizontal[i].continual_count == 1:
                for ip in group_horizontal[i].dipi:
                    group_horizontal[i].pre_dip.append(ip)
            else:
                # check if there is new dip for current sip-dpt connection
                dip_updated = False
                for dip in group_horizontal[i].dipi:
                    if dip not in group_horizontal[i].pre_dip:
                        dip_updated = True
                if dip_updated is False:
                    if group_horizontal[i].continual_count <= window_num:
                        group_horizontal.__delitem__(i)
                        continue
                    else:
                        # time to calulate the entropy
                        if calculateEntropy_horizontal(list_dip=group_horizontal[i].pre_dip):
                            # it is an abnormal connection that entropy exceed the threshold.
                            for flow in group_horizontal[i].attached_flows:
                                if flow not in detected_flows:
                                    detected_flows.append(flow)
                            group_horizontal.__delitem__(i)
                            continue
                        group_horizontal[i].pre_dip.clear()
                        for ip in group_horizontal[i].dipi:
                            group_horizontal[i].pre_dip.append(ip)
                        group_horizontal[i].attached_flows.clear()
                        for flow in group_horizontal[i].flush_flows:
                            group_horizontal[i].attached_flows.append(flow)
                        group_horizontal[i].continual_count = 1
                else:
                    # set the pre_dip
                    u_dip = group_horizontal[i].pre_dip + group_horizontal[i].dipi
                    group_horizontal[i].pre_dip = u_dip
        elif group_horizontal[i].shown_in_current_window is False:
            # current sip-dpt connection did not apears in current time window
            if group_horizontal[i].continual_count <= window_num:
                # It cannot meet the sustainability characteristics
                group_horizontal.__delitem__(i)
                continue
            else:
                # time to calulate the entropy
                if calculateEntropy_horizontal(list_dip=group_horizontal[i].pre_dip):
                    # it is an abnormal connection that entropy exceed the threshold.
                    for flow in group_horizontal[i].attached_flows:
                        if flow not in detected_flows:
                            detected_flows.append(flow)
                group_horizontal.__delitem__(i)
                continue
        i = i + 1

    return


def vertical_operate(timewindow, group_vertical):

    global detected_flows

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
                group_vertical[j].dpti.append(flow[6])
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
                for dpt in group_vertical[i].dpti:
                    if dpt not in group_vertical[i].pre_dpt:
                        dpt_updated = True
                if dpt_updated is False:
                    if group_vertical[i].continual_count <= window_num:
                        group_vertical.__delitem__(i)
                        continue
                    else:
                        # time to calulate the entropy
                        if calculateEntropy_vertical(list_dpt=group_vertical[i].pre_dpt):
                            # it is an abnormal connection that entropy exceed the threshold.
                            for flow in group_vertical[i].attached_flows:
                                if flow not in detected_flows:
                                    detected_flows.append(flow)
                            group_vertical.__delitem__(i)
                            continue
                        group_vertical[i].pre_dpt.clear()
                        for pt in group_vertical[i].dpti:
                            group_vertical[i].pre_dpt.append(pt)
                        group_vertical[i].attached_flows.clear()
                        for flow in group_vertical[i].flush_flows:
                            group_vertical[i].attached_flows.append(flow)
                        group_vertical[i].continual_count = 1
                else:
                    # set the pre_dip
                    u_dpt = group_vertical[i].pre_dpt + group_vertical[i].dpti
                    group_vertical[i].pre_dpt = u_dpt
        elif group_vertical[i].shown_in_current_window is False:
            # current sip-dpt connection did not apears in current time window
            if group_vertical[i].continual_count <= window_num:
                # It cannot meet the sustainability characteristics
                group_vertical.__delitem__(i)
                continue
            else:
                # time to calulate the entropy
                if calculateEntropy_vertical(list_dpt=group_vertical[i].pre_dpt):
                    # it is an abnormal connection that entropy exceed the threshold.
                    for flow in group_vertical[i].attached_flows:
                        if flow not in detected_flows:
                            detected_flows.append(flow)
                group_vertical.__delitem__(i)
                continue
        i = i + 1

    return


def calculateEntropy_horizontal(list_dip):
    if len(list_dip) == 0:
        return False
    diff_dip = []
    dip_entropy = 0
    for ip in list_dip:
        if ip not in diff_dip:
            diff_dip.append(ip)
    for ip in diff_dip:
        i = 0
        counter = 0
        while i < len(list_dip):
            if list_dip[i] == ip:
                counter = counter + 1
            i = i + 1
        per = counter / len(list_dip)
        dip_entropy = dip_entropy + (per * -np.math.log(per, 2))
    if dip_entropy > threshold:
        return True
    return False


def calculateEntropy_vertical(list_dpt):
    if len(list_dpt) == 0:
        return False
    diff_dpt = []
    dpt_entropy = 0
    for pt in list_dpt:
        if pt not in diff_dpt:
            diff_dpt.append(pt)
    for pt in diff_dpt:
        i = 0
        counter = 0
        while i < len(list_dpt):
            if list_dpt[i] == pt:
                counter = counter + 1
            i = i + 1
        per = counter / len(list_dpt)
        dpt_entropy = dpt_entropy + (per * -np.math.log(per, 2))
    if dpt_entropy > threshold:
        return True
    return False


def counter_for_normal(time_window):
    counter = 0
    for flow in time_window:
        if flow[12] != "attacker":
            counter = counter + 1
    return counter


def calculate_precision(count_total, count_total_abnormal, count_total_normal,count_detected_normal,count_detected_abnormal):

    global detected_flows

    if count_total_abnormal == 0:
        count_total_abnormal = 1
    if count_total_normal == 0:
        count_total_normal = 1
    for flow in detected_flows:
        if flow[12] == "attacker":
            count_detected_abnormal = count_detected_abnormal + 1
        else:
            count_detected_normal = count_detected_normal + 1
    TPR = count_detected_abnormal / count_total_abnormal
    FPR = count_detected_normal / count_total_normal
    print("count_detected_abnormal", count_detected_abnormal, "count_total_abnormal", count_total_abnormal, "TPR:", TPR)
    print("count_detected_normal", count_detected_normal, "count_total_normal", count_total_normal, "FPR:", FPR)
    print("count_total", count_total)
    return


def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp


def pre_operation(row_to_pre_operate):
    # skip the dos attack and brute force attack flows
    if row_to_pre_operate[13] == "dos" or row_to_pre_operate[13] == "bruteForce":
        return True
    return False


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
# open the original csv data file
file = csv.reader(open(filepath, 'r'))

group_horizontal = []
group_vertical = []
time_window = []
detected_flows = []
window_num = 5
window_len = 120
threshold = 0.65
timing = 0

count_total = 0
count_total_normal = 0
count_total_abnormal = 0
count_detected_abnormal = 0
count_detected_normal = 0

attribute_line = next(file)
first_line = next(file)
start = get_time(first_line[0])

for row in file:

    if pre_operation(row_to_pre_operate=row):
        continue

    timeArray = time.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")

    if timing == 24 and timeArray.tm_hour == 0:
        timing = 0
    if timeArray.tm_hour >= timing:
        print("Month:", timeArray.tm_mon, "Day:", timeArray.tm_mday, ",", timing % 24, "o'clock")
        timing = timing + 1

    if timeArray.tm_hour >= 6:
        break

    time_window.append(row)

    if get_time(row[0]) - start >= window_len:

        horizontal_operate(timewindow=time_window, group_horizontal=group_horizontal)
        vertical_operate(timewindow=time_window, group_vertical=group_vertical)

        normal_per_window = counter_for_normal(time_window=time_window)
        count_total_normal = count_total_normal + normal_per_window
        count_total_abnormal = count_total_abnormal + len(time_window) - normal_per_window

        count_total = count_total + len(time_window)

        start = get_time(row[0])
        time_window.clear()

calculate_precision(count_total=count_total, count_total_abnormal=count_total_abnormal, count_total_normal=count_total_normal,
                    count_detected_normal=count_detected_normal,count_detected_abnormal=count_detected_abnormal)
