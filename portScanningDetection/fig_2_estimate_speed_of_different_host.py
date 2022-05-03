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


# import matplotlib.pyplot as plt
class Host_temp(object):
    def __init__(self, IP):
        self.IP = IP
        self.window_ewma = []
        self.window_ewma_time_stamp = []


class Host(object):
    def __init__(self, IP, ts, tl, Td, ratio, alpha, suspicious_type):
        self.IP = IP
        # Td is the dynamic time windows's length for different host.
        # default is 120s(2 minutes)
        self.Td = Td
        # alpha is the counter of each host, it is for counting the abnormal flows
        # that appears in the same time window
        self.alpha = alpha
        # set the suspicious type of the host. Such as RST suspicious and ICMP suspicious
        self.suspicious_type = suspicious_type
        # window_sample will record the exact time intervals between every two abnormal flows.
        self.window_sample = []
        self.window_sample.append(self.Td)
        # window_ewma will generate the ewma value based on the window_sample list
        self.window_ewma = []
        self.window_ewma.append(self.Td)
        # record the time stamp of the flow that triggers the change of ewma list
        self.window_ewma_time_stamp = []

        # starts of the one time window
        self.ts = ts
        # last seen time stamp
        self.tl = tl
        # likelihood ratio of sequential test
        self.ratio = ratio

        # flows record those abnormal flows relate to given IP
        self.flows = []


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


def sequential_test(success_num, failed_num, host):
    while success_num > 0:
        host.ratio = host.ratio * (theta1 / theta0)
        success_num = success_num - 1
    host.ratio = host.ratio * host.alpha * ((1 - theta1) / (1 - theta0))
    if host.ratio == 0:
        host.flows.clear()
        host.ratio = 1
    if host.ratio > eta1:
        return 1
    elif host.ratio < eta0:
        return 2
    return 0


def detect_abnormal(flow):
    global hosts_to_print

    # count detected abnormal flows
    c_d_a = 0
    # count detected normal flows
    c_d_n = 0

    # the main process of the algorithm using dynamic time window
    suspicious_type = check_suspicious(flow=flow)
    if suspicious_type == 0:
        # it's not a suspicious flow
        return c_d_a, c_d_n
    else:
        IP = flow[5]
    # it is a suspicious flow, handle this flow by detection algorithm

    # first check if the hosts[] has already recorded the srcIP and suspicious type of this flow
    isNew = True
    i = 0
    while i < len(hosts):
        if hosts[i].IP == IP and hosts[i].suspicious_type == suspicious_type:
            # before detection, check if current host has finished an attack before
            if len(hosts[i].window_ewma) > 5:
                activity_end_test = np.mean(hosts[i].window_ewma[-5:-1])
            else:
                activity_end_test = np.mean(hosts[i].window_ewma)
            if get_time(flow[0]) - hosts[i].tl > 35 * activity_end_test:
                j = 0
                temp_test = True
                while j < len(hosts_to_print):
                    if IP == hosts_to_print[j].IP:
                        temp_test = False
                        break
                    j = j + 1
                if temp_test:
                    hosts_to_print.append(Host_temp(IP=IP))
                    hosts_to_print[-1].window_ewma = hosts_to_print[-1].window_ewma + hosts[i].window_ewma[1:]
                    hosts_to_print[-1].window_ewma_time_stamp = hosts_to_print[-1].window_ewma_time_stamp + \
                                                               hosts[i].window_ewma_time_stamp
                else:
                    hosts_to_print[j].window_ewma = hosts_to_print[j].window_ewma + hosts[i].window_ewma[1:]
                    hosts_to_print[j].window_ewma_time_stamp = hosts_to_print[j].window_ewma_time_stamp + \
                                                               hosts[i].window_ewma_time_stamp
                hosts.__delitem__(i)
                isNew = True
            else:
                current_host = hosts[i]
                isNew = False
        i = i + 1

    if isNew:
        current_host = Host(IP=IP, ts=get_time(flow[0]), tl=get_time(flow[0]), Td=default_window_len,
                            ratio=1, alpha=1, suspicious_type=suspicious_type)
        hosts.append(current_host)
        current_host.flows.append(flow)
        # and if it's the first abnormal flow of the given host, do nothing and waiting for second one.
        return c_d_a, c_d_n

    # record the abnormal flow
    current_host.flows.append(flow)

    # the host of this abnormal flow has already appears before, then run the algorithm
    ti = get_time(flow[0])
    delta_t = ti - current_host.ts
    if delta_t < current_host.Td:
        # the time window is not over yet.

        # append the sample window length according to the time stamp of current flow
        current_host.window_sample.append(ti - current_host.tl)
        # append the EWMA window length according to the EWMA algorithm
        ewma_value = (1 - beta) * current_host.window_ewma[-1] + beta * current_host.window_sample[-1]
        # make sure the ewma value is limited by the range of [5s,1800s]
        if ewma_value < min_window_len:
            ewma_value = min_window_len
        elif ewma_value > max_window_len:
            ewma_value = max_window_len
        current_host.window_ewma.append(ewma_value)
        abnormal_flow_time_stamp = time.strptime(flow[0], "%Y-%m-%d %H:%M:%S.%f")
        current_host.window_ewma_time_stamp.append(
            str(abnormal_flow_time_stamp.tm_hour) + ":" + str(abnormal_flow_time_stamp.tm_min))
        # update the last seen time stamp of the abnormal flow that caused by the host
        current_host.tl = ti

        # count the abnormal counter(alpha) for the given host
        current_host.alpha = current_host.alpha + 1

        # fix the ewma bug here. if alpha is larger than 15, we should consider if the attacker is running a faster scan
        # and then we should adjust the window length immediately.
        if current_host.alpha > 3:
            # turn the current window length Td into the newest ewma window length
            current_host.Td = current_host.window_ewma[-1]

    else:  # delta_t>current_host.Td
        # generate(get) the newest ewma value of the time window's length from window_ewma
        n_ewma = current_host.window_ewma[-1]
        success_num = int((delta_t - current_host.Td) / n_ewma)
        failed_num = 1
        # according to three attributes:success_num,failed_num and alpha, calculate the likelihood ratio
        test_result = sequential_test(success_num=success_num, failed_num=failed_num, host=current_host)
        if test_result == 1:

            if current_host.IP != "192.168.220.16" and current_host.IP != "192.168.220.15":
                print("false alarm:", current_host.IP, "\n attached flow:", current_host.flows[-1])
            # if current_host.IP == "192.168.220.16":
            # print("detected.")
            # it is an abnormal host, we have made decision.
            # then we should calculate the TP and FP
            # count the flows number for TP and FP
            for flow in current_host.flows:
                if re.search('R', flow[10]) is not None:
                    if flow[12] == "victim":
                        c_d_a = c_d_a + 1
                        # record the detected activity ID
                        if flow[14] not in activity_ID:
                            print("detected activity:", flow[14], "at time:", current_host.flows[-1])
                            activity_ID.append(flow[14])
                    else:
                        c_d_n = c_d_n + 1
                elif re.search("ICMP", flow[2]) is not None:
                    if flow[12] == "victim":
                        c_d_a = c_d_a + 1
                        # record the detected activity ID
                        if flow[14] not in activity_ID:
                            print("detected activity:", flow[14], "at time:", current_host.flows[-1])
                            activity_ID.append(flow[14])
                    else:
                        c_d_n = c_d_n + 1
            current_host.ratio = 1
            current_host.flows.clear()
        # elif test_result == 2:
        # current_host.ratio = 1
        # current_host.flows.clear()
        # append the sample window length according to the time stamp of current flow
        current_host.window_sample.append(ti - current_host.tl)
        # append the EWMA window length according to the EWMA algorithm
        ewma_value = (1 - beta) * current_host.window_ewma[-1] + beta * current_host.window_sample[-1]
        # make sure the ewma value is limited by the range of [5s,1800s]
        if ewma_value < min_window_len:
            ewma_value = min_window_len
        elif ewma_value > max_window_len:
            ewma_value = max_window_len
        current_host.window_ewma.append(ewma_value)
        abnormal_flow_time_stamp = time.strptime(flow[0], "%Y-%m-%d %H:%M:%S.%f")
        current_host.window_ewma_time_stamp.append(
            str(abnormal_flow_time_stamp.tm_hour) + ":" + str(abnormal_flow_time_stamp.tm_min))

        current_host.ts = current_host.ts + current_host.Td + success_num * n_ewma
        current_host.tl = ti
        current_host.Td = current_host.window_ewma[-1]
        current_host.alpha = 1

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
    print("detected activity", len(activity_ID), " IDs:", activity_ID)
    return


def draw_ewma_estimating():
    pics = []
    labels = []
    color_set = ['red', 'black', 'yellow', 'blue']
    color_set_index = 0
    max_show_hosts = 0

    for h in hosts:
        if max_show_hosts > 1:
            break
        max_show_hosts = max_show_hosts + 1
        # filter those hosts that cause few abnormal flows
        if len(h.window_ewma_time_stamp) <= 1:
            continue
        labels.append(str(h.IP))
        if color_set_index > 3:
            break
        win_ewma = h.window_ewma[1:]
        x_axis = list()
        y_axis = list()
        i = 0
        while i < len(h.window_ewma_time_stamp):
            if h.window_ewma_time_stamp[i] not in x_axis:
                x_axis.append(h.window_ewma_time_stamp[i])
                y_axis.append(win_ewma[i])
            i = i + 1

        plt.subplot(2, 1, max_show_hosts)
        plt.xlabel('时间（min）', fontproperties="simhei")
        plt.ylabel('EWMA 值（s）', fontproperties="simhei")
        x_major_locator = MultipleLocator(5)
        y_major_locator = MultipleLocator(10)
        ax = plt.gca()
        ax.xaxis.set_major_locator(x_major_locator)
        ax.yaxis.set_major_locator(y_major_locator)
        x, = plt.plot(x_axis, y_axis, color=color_set[color_set_index])
        color_set_index = color_set_index + 1

    plt.show()
    return


def print_timing(row_to_print_time):
    global timing

    timeArray = time.strptime(row_to_print_time[0], "%Y-%m-%d %H:%M:%S.%f")

    if timing == 24 and timeArray.tm_hour == 0:
        timing = 0
    if timeArray.tm_hour >= timing:
        print("Month:", timeArray.tm_mon, "Day:", timeArray.tm_mday, ",", timing % 24, "o'clock")
        timing = timing + 1

    if timeArray.tm_mday < 23:
        return 1
    if timeArray.tm_hour < 7:
        return 1
    if timeArray.tm_hour <= 7 and timeArray.tm_min < 25:
        return 1
    if timeArray.tm_hour == 14 and timeArray.tm_min > 30:
        return 2
    # if timeArray.tm_mday >= 16
    # return 2
    return 0


filepath_week_1 = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
filepath_week_2 = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week2.csv"
filepath_write = "D:\Python\Python37\myexperiment\portScanningDetection\\fig_2_data.csv"

# open the original csv data file
flow_file_week_1 = csv.reader(open(filepath_week_1, 'r'))
flow_file_week_2 = csv.reader(open(filepath_week_2, 'r'))
flow_file_write = csv.writer(open(filepath_write, 'w', newline=''))
# write_file = csv.writer(open(filepath2, 'w', newline=""))

hosts = []  # record the hosts which is related to abnormal flows and ready to detected by the algorithm
hosts_to_print = []
hosts_to_print.append(Host_temp(IP="192.168.220.15"))
hosts_to_print.append(Host_temp(IP="10784_4"))
hosts_to_print.append(Host_temp(IP="192.168.220.16"))

theta0 = 0.8
theta1 = 0.2
eta0 = 0.01
eta1 = 99
beta = 0.2  # beta is the attribute of the EWMA algorithm
default_window_len = 60
min_window_len = 3
max_window_len = 900
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
    print(row)

    # step 1, finish some filtering step
    if pre_operation(row_to_pre_operate=row):
        continue

    # step 2, print the timing information
    time_to_end = print_timing(row_to_print_time=row)
    if time_to_end == 1:
        continue
    elif time_to_end == 2:
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
    if time_to_end == 1:
        continue
    elif time_to_end == 2:
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
# step 6, to show the ewma estimation of each abnormal host's scan rate
# draw_ewma_estimating()
'''for h in hosts:
    if h.IP == "192.168.220.16":
        plt.subplot(2, 1, 1)
        plt.plot(range(len(h.window_sample)), h.window_sample, color='black')
        plt.subplot(2, 1, 2)
        plt.plot(range(len(h.window_ewma)), h.window_ewma, color='red')
        plt.show()
        break'''
i = 0
'''while i < len(hosts):
    if hosts[i].IP == "192.168.220.15":
        hosts_to_print.append(hosts[i])
    elif hosts[i].IP == "10784_4":
        hosts_to_print.append(hosts[i])
    elif hosts[i].IP == "10022_249":
        hosts_to_print.append(hosts[i])
    i = i + 1'''

i = 0
while i < len(hosts_to_print):
    if len(hosts_to_print[i].window_ewma_time_stamp) < 100:
        hosts_to_print.__delitem__(i)
        continue
    if hosts_to_print[i].IP != "10321_204" and hosts_to_print[i].IP != "11184_35" and hosts_to_print[i].IP != "192.168.220.15":
        hosts_to_print.__delitem__(i)
        continue
    i = i + 1

i = 0
while i < len(hosts_to_print):
    flow_file_write.writerow([hosts_to_print[i].IP])
    hour = 7
    minute = 25
    while hour <= 14:
        while minute < 60:
            if hour == 14:
                # write code here
                isNone = True
                j = 0
                while j < len(hosts_to_print[i].window_ewma_time_stamp):
                    if hosts_to_print[i].window_ewma_time_stamp[j] == (str(hour) + ":" + str(minute)):
                        isNone = False
                        break
                    j = j + 1
                if isNone:
                    row_to_write = [str(hour) + ":" + str(minute), None]
                    flow_file_write.writerow(row_to_write)
                else:
                    row_to_write = [str(hour) + ":" + str(minute), hosts_to_print[i].window_ewma[j + 1]]
                    flow_file_write.writerow(row_to_write)
                if minute >= 30:
                    break
            else:
                # write code here
                isNone = True
                j = 0
                while j < len(hosts_to_print[i].window_ewma_time_stamp):
                    if hosts_to_print[i].window_ewma_time_stamp[j] == (str(hour) + ":" + str(minute)):
                        isNone = False
                        break
                    j = j + 1
                if isNone:
                    row_to_write = [str(hour) + ":" + str(minute), None]
                    flow_file_write.writerow(row_to_write)
                else:
                    row_to_write = [str(hour) + ":" + str(minute), hosts_to_print[i].window_ewma[j + 1]]
                    flow_file_write.writerow(row_to_write)
            minute = minute + 1
        minute = 0
        hour = hour + 1
    i = i + 1
