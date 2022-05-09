# this file aims to test the EWMA algorithm using simple sequence of digital number.
import random
import re

import matplotlib.pyplot as plt
import csv
import time


def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp


def pre_operation(row):
    # skip the dos attack and brute force attack flows
    if row[13] == "dos" or row[13] == "bruteForce":
        return True
    return False


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-"
diff_path = ["week1.csv", "week2.csv", "week3.csv", "week4.csv"]
flow_file = []
flow_file.append(csv.reader(open(filepath + diff_path[0], 'r')))
flow_file.append(csv.reader(open(filepath + diff_path[1], 'r')))
flow_file.append(csv.reader(open(filepath + diff_path[2], 'r')))
flow_file.append(csv.reader(open(filepath + diff_path[3], 'r')))

count_dos = 0
count_normal = 0
count_SYN_t1 = 0
count_SYN_t2 = 0
count_SYN_t3 = 0
count_UDP_t1 = 0
count_UDP_t2 = 0
count_UDP_t3 = 0
count_ICMP_t1 = 0
count_ICMP_t2 = 0
count_ICMP_t3 = 0
count_total = 0
udp_activity_t1 = []
udp_activity_t2 = []
udp_activity_t3 = []

timing = 0

i = 0
while i < len(flow_file):
    head = next(flow_file[i])
    for row in flow_file[i]:

        timeArray = time.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
        if timing == 24 and timeArray.tm_hour == 0:
            timing = 0
        if timeArray.tm_hour >= timing:
            print("Month:", timeArray.tm_mon, "Day:", timeArray.tm_mday, ",", timing % 24, "o'clock")
            timing = timing + 1

        count_total = count_total + 1
        if row[12] == "normal":
            count_normal = count_normal + 1
        if re.search("dos", row[13]) is not None:
            count_dos = count_dos + 1

        if row[12] == "attacker" or row[12] == "victim":
            if re.search("UDP", row[2]) is not None:
                if re.search("1", row[15]) is not None and re.search("nmap", row[15]) is not None:
                    count_UDP_t1 = count_UDP_t1 + 1
                    if row[14] not in udp_activity_t1:
                        udp_activity_t1.append(row[14])
                if re.search("2", row[15]) is not None and re.search("nmap", row[15]) is not None:
                    count_UDP_t2 = count_UDP_t2 + 1
                    if row[14] not in udp_activity_t2:
                        udp_activity_t2.append(row[14])
                if re.search("3", row[15]) is not None and re.search("nmap", row[15]) is not None:
                    count_UDP_t3 = count_UDP_t3 + 1
                    if row[14] not in udp_activity_t3:
                        udp_activity_t3.append(row[14])
            elif re.search("ICMP", row[2]) is not None:
                if re.search("1", row[15]) is not None and re.search("nmap", row[15]) is not None:
                    count_ICMP_t1 = count_ICMP_t1 + 1
                if re.search("2", row[15]) is not None and re.search("nmap", row[15]) is not None:
                    count_ICMP_t2 = count_ICMP_t2 + 1
                if re.search("3", row[15]) is not None and re.search("nmap", row[15]) is not None:
                    count_ICMP_t3 = count_ICMP_t3 + 1
            elif re.search("TCP", row[2]) is not None:
                if re.search("1", row[15]) is not None and re.search("nmap", row[15]) is not None:
                    count_SYN_t1 = count_SYN_t1 + 1
                if re.search("2", row[15]) is not None and re.search("nmap", row[15]) is not None:
                    count_SYN_t2 = count_SYN_t2 + 1
                if re.search("3", row[15]) is not None and re.search("nmap", row[15]) is not None:
                    count_SYN_t3 = count_SYN_t3 + 1
    i = i + 1

print("DoS:", count_dos)
print("Normal:", count_normal)
print("SYN:(T1)", count_SYN_t1, count_SYN_t1 / count_total, "(T2)", count_SYN_t2, count_SYN_t2 / count_total, "(T3)",
      count_SYN_t3, count_SYN_t3 / count_total,
      "total:", count_SYN_t1 + count_SYN_t2 + count_SYN_t3, "percentage:",
      (count_SYN_t1 + count_SYN_t2 + count_SYN_t3) / count_total)
print("UDP:(T1)", count_UDP_t1, count_UDP_t1 / count_total, "(T2)", count_UDP_t2, count_UDP_t2 / count_total, "(T3)",
      count_UDP_t3, count_UDP_t3 / count_total,
      "total:", count_UDP_t1 + count_UDP_t2 + count_UDP_t3, "percentage:",
      (count_UDP_t1 + count_UDP_t2 + count_UDP_t3) / count_total)
print("UDP activities:(T1)", len(udp_activity_t1), "(T2)", len(udp_activity_t2), "(T3)", len(udp_activity_t3))
print("ICMP:(T1)", count_ICMP_t1, count_ICMP_t1 / count_total, "(T2)", count_ICMP_t2, count_ICMP_t2 / count_total,
      "(T3)", count_ICMP_t3, count_ICMP_t3 / count_total,
      "total:", count_ICMP_t1 + count_ICMP_t2 + count_ICMP_t3, "percentage:",
      (count_ICMP_t1 + count_ICMP_t2 + count_ICMP_t3) / count_total)
print("Total:", count_total)
