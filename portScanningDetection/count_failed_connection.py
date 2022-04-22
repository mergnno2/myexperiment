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


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
flow_file = csv.reader(open(filepath, 'r'))

flow_data = []

timing = 0

stamps = []
ewma = []
intervals = []
alpha = 0.01
end = 0
start = 0
count_normal_host_1 = 0
count_normal_host_2 = 0
count_attacker = 0

failed_connection_normal_host_1 = [0]
failed_connection_normal_host_2 = [0]
failed_connection_attacker = [0]

head = next(flow_file)
first_row = next(flow_file)
start = get_time(first_row[0])

for row in flow_file:

    if pre_operation(row=row) is True:
        continue

    timeArray = time.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")

    if timing == 24 and timeArray.tm_hour == 0:
        timing = 0
    if timeArray.tm_hour >= timing:
        print("Month:", timeArray.tm_mon, "Day:", timeArray.tm_mday, ",", timing % 24, "o'clock")
        timing = timing + 1
    if timeArray.tm_mday >= 16:
        break

    end = get_time(row[0])
    if end - start > 300:
        failed_connection_normal_host_1.append(failed_connection_normal_host_1[-1] + count_normal_host_1)
        failed_connection_normal_host_2.append(failed_connection_normal_host_2[-1] + count_normal_host_2)
        failed_connection_attacker.append(failed_connection_attacker[-1] + count_attacker)
        count_normal_host_1 = 0
        count_normal_host_2 = 0
        count_attacker = 0
        start = end
    else:
        if re.search('R', row[10]) is not None:
            if row[5] == "192.168.210.5":
                count_normal_host_1 = count_normal_host_1 + 1
            elif row[5] == "192.168.200.9":
                count_normal_host_2 = count_normal_host_2 + 1
            elif row[5] == "192.168.220.16":
                count_attacker = count_attacker + 1

pics = []
labels = ['Normal Host - "192.168.210.5"', 'Normal Host - "192.168.200.9"', 'Attacker']
pic_0, = plt.plot(failed_connection_normal_host_1, color='green')
pic_1, = plt.plot(failed_connection_normal_host_2, color='blue', linestyle='--')
pic_2, = plt.plot(failed_connection_attacker, color='red', linestyle=':')
pics.append(pic_0)
pics.append(pic_1)
pics.append(pic_2)

plt.legend(pics, labels, loc='upper right')
plt.show()
