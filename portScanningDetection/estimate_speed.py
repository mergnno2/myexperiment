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
counter = 0
pkt_t1 = []
pkt_t2 = []
pkt_t3 = []

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

    if row[12] == "attacker":
        end = get_time(row[0])
        if end - start > 60:
            if re.search("1", row[15]) is not None:
                pkt_t1.append(counter)
                pkt_t2.append(None)
                pkt_t3.append(None)
            elif re.search("2", row[15]) is not None:
                pkt_t2.append(counter)
                pkt_t1.append(None)
                pkt_t3.append(None)
            elif re.search("3", row[15]) is not None:
                pkt_t3.append(counter)
                pkt_t1.append(None)
                pkt_t2.append(None)
            counter = 0
            start = end
        else:
            counter = counter + 1
        '''if len(stamps) == 0:
            stamps.append(get_time(row[0]))
        else:
            # new interval is: get_time(row[0]) - stamps[-1]
            # ewma.append((1 - alpha) * ewma[-1] + alpha * get_time(row[0]) - stamps[-1])
            intervals.append(get_time(row[0]) - stamps[-1])
            stamps.append(get_time(row[0]))'''

    #if timeArray.tm_mday >= 16:
        #break

pics = []
labels = ['-T1', '-T2', '-T3']
pic_0, = plt.plot(pkt_t1, color='blue')
pic_1, = plt.plot(pkt_t2, color='green', linestyle=':')
pic_2, = plt.plot(pkt_t3, color='red', linestyle='--')
pics.append(pic_0)
pics.append(pic_1)
pics.append(pic_2)

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

plt.legend(pics, labels, loc='upper right')
plt.show()
