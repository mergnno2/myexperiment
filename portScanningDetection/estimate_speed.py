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


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week2.csv"
filepath_write = "D:\Python\Python37\myexperiment\portScanningDetection\\figure_1_estimate_interval.csv"
flow_file = csv.reader(open(filepath, 'r'))
flow_file_write = csv.writer(open(filepath_write, 'w', newline=''))

flow_data = []

timing = 0

intervals = []
alpha = 0.01
end = 0
start = 0
counter = 0
isFirst = True

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

    if timeArray.tm_mday < 23:
        continue
    if timeArray.tm_hour < 7:
        continue
    if timeArray.tm_hour <= 7 and timeArray.tm_min < 25:
        continue
    if timeArray.tm_hour == 14 and timeArray.tm_min > 30:
        break

    if row[12] == "attacker":
        flow_data.append(row)

start = get_time(flow_data[0][0])
i = 1
while i < len(flow_data):

    if pre_operation(row=flow_data[i]) is True:
        continue
    end = get_time(flow_data[i][0])
    if end - start < 0:
        intervals.append(0)
    else:
        intervals.append(end - start)
    start = end

    i = i + 1
i = 0
while i < len(intervals):
    flow_file_write.writerow([intervals[i]])
    i = i + 1

'''
pics_2 = []
labels_2 = ['-T1', '-T2', '-T3']
pic_1_0, = plt.plot(pkt_t1, color='blue')
pic_1_1, = plt.plot(pkt_t2, color='green', linestyle=':')
pic_1_2, = plt.plot(pkt_t3, color='red', linestyle='--')
pics_2.append(pic_1_0)
pics_2.append(pic_1_1)
pics_2.append(pic_1_2)

count_avg = 0
avg_1 = 0
avg_2 = 0
avg_3 = 0
for item in pkt_t1:
    if item is not None:
        avg_1 = avg_1 + item
        count_avg = count_avg + 1
if count_avg != 0:
    print("-T1 average(pkt_per_5s):", avg_1 / count_avg)
count_avg = 0
for item in pkt_t2:
    if item is not None:
        avg_2 = avg_2 + item
        count_avg = count_avg + 1
if count_avg != 0:
    print("-T2 average(pkt_per_5s):", avg_2 / count_avg)
count_avg = 0
for item in pkt_t3:
    if item is not None:
        avg_3 = avg_3 + item
        count_avg = count_avg + 1
if count_avg != 0:
    print("-T3 average(pkt_per_5s):", avg_3 / count_avg)
count_avg = 0

plt.legend(pics_2, labels_2, loc='upper right')
plt.show()'''
