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


class Host(object):
    def __init__(self, IP, ts, tl, Td, ratio, alpha):
        self.IP = IP
        # Td is the dynamic time windows's length for different host.
        # default is 120s(2 minutes)
        self.Td = Td
        # alpha is the counter of each host, it is for counting the abnormal flows
        # that appears in the same time window
        self.alpha = alpha
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


class Target(object):
    # indicate the host under the TCP/UDP connections.
    def __init__(self, IP, port):
        self.IP = IP
        self.port = port


class Connection(object):
    def __init__(self, src, dst, last_seen_time, con_1, con_2):
        self.src = Target(src.IP, src.port)
        self.dst = Target(dst.IP, dst.port)
        self.last_seen_time = last_seen_time
        self.con_1 = con_1
        self.con_2 = con_2


def check_abnormal(flow):
    # check one flow if it is a abnormal flow by counting ICMP/NeIP/NeTCP
    '''if re.search("_", flow[5]) is not None:
        return 0
    elif re.search("_", flow[3]) is not None:
        return 0'''
    if re.search("DNS", flow[5]) is not None:
        return 0
    elif re.search('F', flow[10]) is not None:
        return 0
    elif re.search('S', flow[10]) is not None:
        return 0
    elif re.search('P', flow[10]) is not None:
        return 0
    elif re.search('R', flow[10]) is not None:
        return 1
    elif re.search("3\.", flow[6]) is not None:
        return 1
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
        return True
    return False


def entropy_test(flows):
    if len(flows) == 0:
        return False
    src_IP_entropy = 0
    src_Port_entropy = 0
    diff_src_IP = []
    diff_src_Port = []
    for flow in flows:
        if flow[3] not in diff_src_IP:
            diff_src_IP.append(flow[3])
        if flow[4] not in diff_src_Port:
            diff_src_Port.append(flow[4])
    for ip in diff_src_IP:
        counter = 0
        i = 0
        while i < len(flows):
            if ip == flows[i][3]:
                counter = counter + 1
            i = i + 1
        per = float(counter / len(flows))
        src_IP_entropy = src_IP_entropy + (per * -np.math.log(per, 2))
    for port in diff_src_Port:
        counter = 0
        i = 0
        while i < len(flows):
            if port == flows[i][4]:
                counter = counter + 1
            i = i + 1
        per = float(counter / len(flows))
        src_Port_entropy = src_Port_entropy + (per * -np.math.log(per, 2))
    if src_IP_entropy > entropy_threshold_IP or src_Port_entropy > entropy_threshold_Port:
        return True
    return False


def detect_abnormal(flow):
    # count detected abnormal flows
    c_d_a = 0
    # count detected normal flows
    c_d_n = 0

    # the main process of the algorithm using dynamic time window
    is_abnormal = check_abnormal(flow=flow)
    if is_abnormal == 0:
        return c_d_a, c_d_n
    elif is_abnormal == 1:
        IP = flow[5]
    # it is an abnormal flow, handle this flow by detection algorithm

    # first check if the hosts[] has already recorded the srcIP of this flow
    isNew = True
    i = 0
    while i < len(hosts):
        if hosts[i].IP == IP:
            isNew = False
            current_host = hosts[i]
        i = i + 1

    if isNew:
        current_host = Host(IP=IP, ts=get_time(flow[0]), tl=get_time(flow[0]), Td=default_window_len, ratio=1, alpha=1)
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
        current_host.window_ewma_time_stamp.append(str(abnormal_flow_time_stamp.tm_min))
        # update the last seen time stamp of the abnormal flow that caused by the host
        current_host.tl = ti

        # count the abnormal counter(alpha) for the given host
        current_host.alpha = current_host.alpha + 1

        # fix the ewma bug here. if alpha is larger than 15, we should consider if the attacker is running a faster scan
        # and then we should adjust the window length immediately.
        if current_host.alpha > 30:
            # turn the current window length Td into the newest ewma window length
            current_host.Td = current_host.window_ewma[-1]

    else:  # delta_t>current_host.Td
        # generate(get) the newest ewma value of the time window's length from window_ewma
        n_ewma = current_host.window_ewma[-1]
        success_num = int((delta_t - current_host.Td) / n_ewma)
        failed_num = 1
        # according to three attributes:success_num,failed_num and alpha, calculate the likelihood ratio
        if sequential_test(success_num=success_num, failed_num=failed_num, host=current_host):
            # and entropy_test(flows=current_host.flows):

            if current_host.IP != "192.168.220.16" and current_host.IP != "192.168.220.15":
                print("false alarm:", current_host.IP, "\n attached flow:", current_host.flows[-1])
            # it is an abnormal host, we have made decision.
            # then we should calculate the TP and FP
            # count the flows number for TP and FP
            for flow in current_host.flows:
                if re.search('R', flow[10]) is not None:
                    if flow[12] == "normal" or flow[12] == "attacker":
                        c_d_n = c_d_n + 1
                    elif flow[12] == "victim":
                        c_d_a = c_d_a + 1
                        # record the detected activity ID
                        if flow[14] not in activity_ID:
                            print("detected activity:", flow[14], "at time:", current_host.flows[-1])
                            activity_ID.append(flow[14])
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
            # if current_host.IP != "192.168.220.16":
            # print("Abnormal host:", current_host.IP, "Last seen flow:", current_host.flows[-1])
            current_host.flows.clear()

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
        current_host.window_ewma_time_stamp.append(str(abnormal_flow_time_stamp.tm_min))

        current_host.ts = current_host.ts + current_host.Td + success_num * n_ewma
        current_host.tl = ti
        current_host.Td = current_host.window_ewma[-1]
        current_host.alpha = 1
        # if current_host.IP == "192.168.220.16":
        # print(current_host.ratio)

    return c_d_a, c_d_n


def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp


def pre_operation(row):
    # skip the dos attack and brute force attack flows
    if row[13] == "dos" or row[13] == "bruteForce":
        # if row[13] == "bruteForce":
        return True
    return False


def counter_for_abnormal(row):
    if re.search('R', row[10]) is not None and row[12] == "victim":
        return 1
    elif re.search("ICMP", row[2]) is not None and row[12] == "victim":
        return 1
    return 0


def counter_for_normal(row):
    if row[12] == "normal":
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
    print("detected activity IDs:", activity_ID)
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


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
# open the original csv data file
flow_file = csv.reader(open(filepath, 'r'))
# write_file = csv.writer(open(filepath2, 'w', newline=""))

hosts = []  # record the hosts which is related to abnormal flows and ready to detected by the algorithm

theta0 = 0.8
theta1 = 0.2
eta0 = 0.01
eta1 = 99
beta = 0.2  # beta is the attribute of the EWMA algorithm
entropy_threshold_IP = 0.9
entropy_threshold_Port = 0.9
min_window_len = 5
max_window_len = 300
default_window_len = 120
timing = 0

# counters for calculate the precision
count_total = 0
count_total_normal = 0
count_total_abnormal = 0
count_detected_abnormal = 0
count_detected_normal = 0
activity_ID = []  # record the activity ID that system detected

head = next(flow_file)
for row in flow_file:

    if pre_operation(row=row) is True:
        continue

    timeArray = time.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")

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
    if timeArray.tm_hour >= 8:
        break

    # then testify each flow(row) if its ICMP error or a TCP-RST package
    # then run the abnormal detection algorithm using dynamic time window
    (count_a, count_n) = detect_abnormal(flow=row)

    # update all the counters for calculate the TP and FP
    count_total = count_total + 1
    count_total_abnormal = count_total_abnormal + counter_for_abnormal(row=row)
    count_total_normal = count_total_normal + counter_for_normal(row=row)
    count_detected_abnormal = count_detected_abnormal + count_a
    count_detected_normal = count_detected_normal + count_n

# once the program ends, we can calculate the precision of the algorithm
calculate_precision(count_total=count_total, count_total_abnormal=count_total_abnormal,
                    count_total_normal=count_total_normal, count_detected_abnormal=count_detected_abnormal,
                    count_detected_normal=count_detected_normal)
# draw_ewma_estimating()
