# this file aims to test the EWMA algorithm using simple sequence of digital number.
import random
import re

import matplotlib.pyplot as plt
import csv
import time

from matplotlib.pyplot import MultipleLocator


def print_timing(row_to_print_time):
    global timing
    global start_1
    global start_2

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
        start_1 = get_time(row_to_print_time[0])
        start_2 = get_time(row_to_print_time[0])
        return 1
    if timeArray.tm_hour == 14 and timeArray.tm_min > 30:
        return 2
    # if timeArray.tm_hour >= 12:
    # return 2
    return 0


def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp


def pre_operation(row):
    # skip the dos attack and brute force attack flows
    if row[13] == "dos" or row[13] == "bruteForce":
        return True
    return False


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week2.csv"
filepath_write = "D:\Python\Python37\myexperiment\portScanningDetection\\figure_1_data.csv"
flow_file = csv.reader(open(filepath, 'r'))
flow_file_write = csv.writer(open(filepath_write, 'w', newline=''))

flow_data = []

timing = 0
timer_1 = []
timer_2 = []

stamps = []
ewma = []
intervals = []
alpha = 0.01
end_1 = 0
start_1 = 0
end_2 = 0
start_2 = 0
start_2_flag = False
counter = 0
count_normal_host_1 = 0
count_normal_host_2 = 0
count_attacker = 0

failed_connection_normal_host_1 = [0]
failed_connection_normal_host_2 = [0]
failed_connection_attacker = [0]
pkt_t1 = []
pkt_t2 = []
pkt_t3 = []
probes = []

head = next(flow_file)
first_row = next(flow_file)
start_1 = get_time(first_row[0])
start_2 = get_time(first_row[0])

for row in flow_file:

    if pre_operation(row=row) is True:
        continue

    time_to_end = print_timing(row_to_print_time=row)
    if time_to_end == 1:
        continue
    elif time_to_end == 2:
        break

    timeArray_local = time.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
    # count RST here
    end_1 = get_time(row[0])
    if end_1 - start_1 > 300:
        timer_1.append(str(timeArray_local.tm_hour)+":"+str(timeArray_local.tm_min))
        failed_connection_normal_host_1.append(failed_connection_normal_host_1[-1] + count_normal_host_1)
        failed_connection_normal_host_2.append(failed_connection_normal_host_2[-1] + count_normal_host_2)
        failed_connection_attacker.append(failed_connection_attacker[-1] + count_attacker)
        count_normal_host_1 = 0
        count_normal_host_2 = 0
        count_attacker = 0
        start_1 = end_1
    else:
        if re.search('R', row[10]) is not None and re.search('P', row[10]) is None and re.search('F', row[10]) is None \
                and re.search('U', row[10]) is None:
            if row[5] == "192.168.210.5":
                count_normal_host_1 = count_normal_host_1 + 1
            elif row[5] == "192.168.200.9":
                count_normal_host_2 = count_normal_host_2 + 1
            elif row[5] == "192.168.220.15":
                count_attacker = count_attacker + 1

    # count probe here

    end_2 = get_time(row[0])
    if end_2 - start_2 > 300:
        timer_2.append(str(timeArray_local.tm_hour)+":"+str(timeArray_local.tm_min))
        probes.append(counter)
        counter = 0
        start_2 = end_2
    else:
        if row[12] == "attacker":
            counter = counter + 1

i = 0
while i < len(probes):
    if i >= 7 and i <= 48:
        pkt_t1.append(probes[i])
        pkt_t2.append(None)
    elif i >= 54 and i <= 78:
        pkt_t1.append(None)
        pkt_t2.append(probes[i])
    else:
        pkt_t1.append(None)
        pkt_t2.append(None)
    i = i + 1

print(len(probes))
print(len(failed_connection_attacker))
print(len(failed_connection_normal_host_1))
print(len(failed_connection_normal_host_2))
print(len(pkt_t1))
print(len(pkt_t2))
print(len(timer_1))
print(len(timer_2))

flow_file_write.writerow(["failed_connection_attacker------------"])
i = 1
while i < len(failed_connection_attacker):
    flow_file_write.writerow([timer_1[i-1],failed_connection_attacker[i]])
    i = i + 1


flow_file_write.writerow(["failed_connection_normal_host_1------------"])
i = 1
while i < len(failed_connection_normal_host_1):
    flow_file_write.writerow([timer_1[i-1],failed_connection_normal_host_1[i]])
    i = i + 1


flow_file_write.writerow(["failed_connection_normal_host_2------------"])
i = 1
while i < len(failed_connection_normal_host_2):
    flow_file_write.writerow([timer_1[i-1],failed_connection_normal_host_2[i]])
    i = i + 1


flow_file_write.writerow(["pkt_t1------------"])
i = 0
while i < len(pkt_t1):
    flow_file_write.writerow([timer_1[i],pkt_t1[i]])
    i = i + 1


flow_file_write.writerow(["pkt_t2------------"])
i = 0
while i < len(pkt_t2):
    flow_file_write.writerow([timer_1[i],pkt_t2[i]])
    i = i + 1

flow_file_write.writerow(["end"])
'''
plt.subplot(1, 2, 1)
plt.title("(a)", y=-0.2)
plt.xlim(-5, 85)
plt.ylim(-25, 1000)
x_major_locator = MultipleLocator(20)
y_major_locator = MultipleLocator(200)
ax = plt.gca()
ax.xaxis.set_major_locator(x_major_locator)
ax.yaxis.set_major_locator(y_major_locator)

plt.xlabel('Time (*5min)', fontproperties="simhei", fontsize=15, loc="right")
plt.ylabel('Received RST Pkt', fontproperties="simhei", fontsize=15, loc="top")
plt.xticks(fontsize=12)
plt.yticks(fontsize=12)

pics_1 = []
labels_1 = ['Attacker', 'Normal Host', 'Normal Host']
pic_0_0, = plt.plot(failed_connection_attacker, color='black', linestyle='-')
pic_0_1, = plt.plot(failed_connection_normal_host_1, color='black', linestyle='--')
pic_0_2, = plt.plot(failed_connection_normal_host_2, color='black', linestyle=':')
pics_1.append(pic_0_0)
pics_1.append(pic_0_1)
pics_1.append(pic_0_2)
plt.legend(pics_1, labels_1, loc='upper left')

plt.subplot(1, 2, 2)
plt.title("(b)", y=-0.2)
plt.xlim(-5, 85)
plt.ylim(-25, 1000)
x_major_locator = MultipleLocator(20)
y_major_locator = MultipleLocator(200)
ax = plt.gca()
ax.xaxis.set_major_locator(x_major_locator)
ax.yaxis.set_major_locator(y_major_locator)

plt.xlabel('Time (*5min)', fontproperties="simhei", fontsize=15, loc="right")
plt.ylabel('Sent Probe', fontproperties="simhei", fontsize=15, loc="top")
plt.xticks(fontsize=12)
plt.yticks(fontsize=12)

pics_2 = []
labels_2 = ['Scan Rate -T1', 'Scan Rate -T2']
pic_1_0, = plt.plot(pkt_t1, color='black', linestyle='-')
pic_1_1, = plt.plot(pkt_t2, color='black', linestyle='--')
# pic_1_2, = plt.plot(pkt_t3, color='black', linestyle='dotted')
pics_2.append(pic_1_0)
pics_2.append(pic_1_1)
# pics_2.append(pic_1_2)
plt.legend(pics_2, labels_2, loc='upper left')

plt.show()'''
