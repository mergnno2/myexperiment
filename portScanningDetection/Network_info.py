# This code intend to get the information about the host and their opening ports from CIDDS-001-Internal data set.
import re
import pandas as pd
import time
import numpy as np
import csv


def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp

# latest version that perform a nice result. However, it has some bug, that is: network_info
# should be recorded when the detecting process is running, not recorded before the
# process. Plus, it should not consider the attribute "normal" of which flow has.
# That's mean that this algorithm is actually supervised. That is not right.
filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
# open the original csv data file
file = csv.reader(open(filepath, 'r'))

start_bound = 0
end_bound = 21

timing = 0

network_info = {}
isFirstrow = True
head = next(file)
firstrow = next(file)
start = get_time(firstrow[0])
window_index = 0

for row in file:

    if isFirstrow:
        isFirstrow = False

    end = get_time(row[0])
    timeArray = time.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
    if timeArray.tm_hour > timing:
        print(str(timeArray.tm_hour) + "o'clock")
        timing = timing + 1
    elif timeArray.tm_hour < start_bound:
        continue
    elif timeArray.tm_hour >= end_bound:
        # Calculate precision here.

        items = network_info.items()
        with open('Network_Information.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            for item in items:
                l = []
                l.append(item[0])
                r = l + item[1]
                writer.writerow(r)

        # pd.DataFrame(network_info).to_csv("Network_Information.csv")
        exit(0)
    if row[12] != "normal" or row[2] == "ICMP":
        continue
    IP = row[3]
    port = row[4]
    result = network_info.get(IP)
    if result == None:
        ports = []
        ports.append(port)
        item = {IP: ports}
        network_info.update(item)
    else:
        if port in result:
            continue
        else:
            result.append(port)
            network_info[IP] = result
