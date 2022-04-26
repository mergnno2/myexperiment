# This code refer to the paper "Detection of slow port scans in flow-based network traffic"
# The data set used by the above paper is also "CIDDS-001"
# Start date: 09.09.2021
import re
import pandas as pd
import time
import numpy as np
import csv
import matplotlib.pyplot as plt


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
    dst_IP = flow[5]
    dst_Port = flow[6]
    if re.search("TCP", flow[2]) is not None:
        result_dst = network_info.get(dst_IP)
        if result_dst is None:
            return 1
        elif dst_Port not in result_dst:
            return 2
    elif re.search("3\.", flow[6]) is not None:
        return 3
    return 0


def sequential_test(success_num, failed_num, host):
    while success_num > 0:
        host.ratio = host.ratio * (theta1 / theta0)
        success_num = success_num - 1
    host.ratio = host.ratio * host.alpha * ((1 - theta1) / (1 - theta0))
    if host.ratio == 0:
        host.flows.clear()
        host.ratio = 1
    if host.ratio > eita1:
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
    elif is_abnormal == 3:
        IP = flow[5]
    else:
        IP = flow[3]

    # it is an abnormal flow, handle this flow by detection algorithm

    # first check if the hosts[] has already recorded the srcIP of this flow
    isNew = True
    i = 0
    while i < len(hosts):
        if hosts[i].IP == IP:
            isNew = False
            current_host = hosts[i]
        i = i + 1
    # for host in hosts:
    #    if host.IP == IP:
    #        isNew = False
    #        current_host = host
    if isNew:
        current_host = Host(IP=IP, ts=get_time(flow[0]), tl=get_time(flow[0]), Td=deafult_window_len, ratio=1, alpha=1)
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
        ewma_value = (1 - beita) * current_host.window_ewma[-1] + beita * current_host.window_sample[-1]
        # make sure the ewma value is limited by the range of [5s,1800s]
        if ewma_value < 5:
            ewma_value = 5
        elif ewma_value > 1800:
            ewma_value = 1800
        current_host.window_ewma.append(ewma_value)
        abnormal_flow_time_stamp = time.strptime(flow[0], "%Y-%m-%d %H:%M:%S.%f")
        current_host.window_ewma_time_stamp.append(str(abnormal_flow_time_stamp.tm_min))
        # update the last seen time stamp of the abnormal flow that caused by the host
        current_host.tl = ti

        # count the abnormal counter(alpha) for the given host
        current_host.alpha = current_host.alpha + 1

        # fix the ewma bug here. if alpha is larger than 15, we should consider if the attacker is running a faster scan
        # and then we should adjust the window length immediately.
        if current_host.alpha > 5:
            # turn the current window length Td into the newest ewma window length
            current_host.Td = current_host.window_ewma[-1]

    else:  # delta_t>current_host.Td
        # generate(get) the newest ewma value of the time window's length from window_ewma
        n_ewma = current_host.window_ewma[-1]
        success_num = int((delta_t - current_host.Td) / n_ewma)
        failed_num = 1
        # according to three attributes:success_num,failed_num and alpha, calculate the likelihood ratio
        if sequential_test(success_num=success_num, failed_num=failed_num, host=current_host):
            if current_host.IP != "192.168.220.16" and current_host.IP != "192.168.220.15":
                print("false alarm:", current_host.IP, "\n attached flow:", current_host.flows[-1])

            # it is an abnormal host, we have made decision.
            # then we should calculate the TP and FP
            # count the flows number for TP and FP
            for flow in current_host.flows:
                if re.search("TCP", flow[2]) is not None:
                    if flow[12] == "normal" or flow[12] == "victim":
                        c_d_n = c_d_n + 1
                    elif flow[12] == "attacker":
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
        ewma_value = (1 - beita) * current_host.window_ewma[-1] + beita * current_host.window_sample[-1]
        # make sure the ewma value is limited by the range of [5s,1800s]
        if ewma_value < 5:
            ewma_value = 5
        elif ewma_value > 1800:
            ewma_value = 1800
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


def update_network_info(flow):
    # update the parameter 'network_info' (which is a dictionary that recored the <ip,ports> information) here:
    if re.search("TCP", flow[2]) is None:
        return
    src = Target(IP=flow[3], port=flow[4])
    dst = Target(IP=flow[5], port=flow[6])
    T = get_time(flow[0])
    result_src = network_info.get(src.IP)
    result_dst = network_info.get(dst.IP)
    if result_src is not None and result_dst is not None:
        # if <sip,spt> and <dip,dpt> has already both recorded, then do nothing.
        if src.port in result_src and dst.port in result_dst:
            return
    isNew = True
    i = 0
    while i < len(connections):
        if connections[i].src.IP == src.IP and connections[i].src.port == src.port \
                and connections[i].dst.IP == dst.IP and connections[i].dst.port == dst.port:
            isNew = False
            if re.search("A", flow[10]) is not None and re.search("S", flow[10]) is not None:
                connections[i].last_seen_time = T
            else:
                connections.__delitem__(i)
            return
        elif connections[i].src.IP == dst.IP and connections[i].src.port == dst.port \
                and connections[i].dst.IP == src.IP and connections[i].dst.port == src.port:
            isNew = False
            if re.search("A", flow[10]) is not None and re.search("S", flow[10]) is not None:
                if T - connections[i].last_seen_time > 6:
                    connections[i].src.IP = dst.IP
                    connections[i].src.port = dst.port
                    connections[i].dst.IP = src.IP
                    connections[i].dst.port = src.port
                else:
                    connections[i].con_2 = True
                    if result_src is not None:
                        if src.port not in result_src:
                            result_src.append(src.port)
                            network_info.update({src.IP: result_src})
                    else:
                        src_ports = []
                        src_ports.append(src.port)
                        network_info.update({src.IP: src_ports})
                    if result_dst is not None:
                        if dst.port not in result_dst:
                            result_dst.append(dst.port)
                            network_info.update({dst.IP: result_dst})
                    else:
                        dst_ports = []
                        dst_ports.append(dst.port)
                        network_info.update({dst.IP: dst_ports})
                    connections.__delitem__(i)
            else:
                connections.__delitem__(i)
            return
        i = i + 1
    if isNew and re.search("A", flow[10]) is not None and re.search("S", flow[10]) is not None:
        connections.append(Connection(src=src, dst=dst, last_seen_time=T, con_1=True, con_2=False))
    return


def update_network_info_for_victim(flow):
    # this method is for those flows which are related to the failed connections between attacker and victim.
    # obviously, victim didn't connect to the invalid TCP port on the attacker's machine, they just did the
    # regular response to them.
    # Therefore, any flows that include TCP flags 'A' are considered as normal ( in the case of only SYN scan exist.)
    if re.search("TCP", flow[2]) is None or re.search("A", flow[10]) is None:
        return
    dst = Target(IP=flow[5], port=flow[6])
    result = network_info.get(dst.IP)
    if result is None:
        ports = []
        ports.append(dst.port)
        network_info.update({dst.IP: ports})
    else:
        if dst.port not in result:
            result.append(dst.port)
            network_info.update({dst.IP: result})
    return


def pre_operation(row):
    # skip the dos attack and brute force attack flows
    if row[13] == "dos" or row[13] == "bruteForce":
        # if row[13] == "bruteForce":
        return True
    return False


def counter_for_abnormal(row):
    if re.search("TCP", row[2]) is not None and row[12] == "attacker":
        return 1
    elif re.search("ICMP", row[2]) is not None and row[12] == "victim":
        return 1
    return 0


def calculate_precision(count_total, count_total_abnormal, count_total_normal,
                        count_detected_abnormal, count_detected_normal):
    if count_total_abnormal == 0:
        count_total_abnormal = 1
    if count_total_normal == 0:
        count_total_normal = 1
    count_total_normal = count_total - count_total_abnormal
    TP = count_detected_abnormal / count_total_abnormal
    FP = count_detected_normal / count_total_normal
    print("count_detected_abnormal", count_detected_abnormal, "count_total_abnormal", count_total_abnormal, "TP:", TP)
    print("count_detected_normal", count_detected_normal, "count_total_normal", count_total_normal, "FP:", FP)
    print("count_total", count_total)
    print("detected activity IDs:", activity_ID)
    return


def draw_ewma_estimating():
    pics = []
    labels = []
    color_set = ['red', 'black', 'yellow', 'blue']
    color_set_index = 0
    for h in hosts:
        label = h.IP
        labels.append(str(label))
        if color_set_index > 3:
            break
        win_ewma = h.window_ewma[1:]
        if len(h.window_ewma_time_stamp) <= 1:
            continue
        else:
            time_stamp_start = h.window_ewma_time_stamp[0]

        x, = plt.plot(h.window_ewma_time_stamp, win_ewma, color=color_set[color_set_index])
        pics.append(x)
        color_set_index = color_set_index + 1

    plt.legend(pics, labels, loc='upper right')
    plt.show()
    return


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
# filepath2 = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001-internal-week1_write.csv"
# open the original csv data file
flow_file = csv.reader(open(filepath, 'r'))
# write_file = csv.writer(open(filepath2, 'w', newline=""))

flow_data = []
connections = []  # used to mark every connections (those TCP connections that unfinished) as flow comes.
srcIP_ratio = {}  # dictionary for every IP in network for recording the ratio.
network_info = {}  # mark the valid <IP,port> information. host <IP> opend the port <Port>
hosts = []  # record the hosts which is related to abnormal flows and ready to detected by the algorithm
activity_ID = []  # record the activity ID that system detected

theta0 = 0.8
theta1 = 0.2
eita0 = 0.01
eita1 = 99
# beita is the attribute of the EWMA algorithm
beita = 0.9
# window_length = 20  # seconds
deafult_window_len = 120
timing = 0

# counters for calculate the precision
count_total = 0
count_total_normal = 0
count_total_abnormal = 0
count_detected_abnormal = 0
count_detected_normal = 0

# these valid IPs are observed from the given network topology
valid_IPs = ['192.168.100.2', '192.168.100.3', '192.168.100.4', '192.168.100.5', '192.168.100.6',
             '192.168.200.2', '192.168.200.3', '192.168.200.4', '192.168.200.5', '192.168.200.8', '192.168.200.9',
             '192.168.210.2', '192.168.210.3', '192.168.210.4', '192.168.210.5',
             '192.168.220.2', '192.168.220.3', '192.168.220.4', '192.168.220.5', '192.168.220.6',
             '192.168.220.7', '192.168.220.8', '192.168.220.9', '192.168.220.10', '192.168.220.11',
             '192.168.220.12', '192.168.220.13', '192.168.220.14', '192.168.220.15', '192.168.220.16',
             'DNS', 'EXT_SERVER']
# record the above valid_IPs into network_info
for ip in valid_IPs:
    ports = []
    network_info.update({ip: ports})

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

    # we need to use this row to update the Network_information, which is
    # recorded the information about the successful TCP connections and <ip,port>.
    update_network_info(flow=row)
    update_network_info_for_victim(flow=row)

    # record the flow data
    # flow_data.append(flow=row)
    # then testify each flow(row) if its ICMP/NeIP/NeTCP counter is not null
    # then run the abnormal detection algorithm using dynamic time_window
    (count_a, count_n) = detect_abnormal(flow=row)

    # update all the counters for calculate the TP and FP
    count_total = count_total + 1
    count_total_abnormal = count_total_abnormal + counter_for_abnormal(row=row)
    count_detected_abnormal = count_detected_abnormal + count_a
    count_detected_normal = count_detected_normal + count_n

# once the program ends, we can calculate the precision of the algorithm
calculate_precision(count_total=count_total, count_total_abnormal=count_total_abnormal,
                    count_total_normal=count_total_normal, count_detected_abnormal=count_detected_abnormal,
                    count_detected_normal=count_detected_normal)
# draw_ewma_estimating()
