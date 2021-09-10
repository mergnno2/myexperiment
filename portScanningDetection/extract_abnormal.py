import re

import pandas as pd
import time
import numpy as np
import csv

filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
filepath_write = "D:\Python\Python37\myexperiment\portScanningDetection\\abnormal.csv"
# open the original csv data file
file = csv.reader(open(filepath, 'r'))

timewindow = []
timing = 0

isFirstrow = True
head = next(file)
firstrow = next(file)
timeArray = time.strptime(firstrow[0], "%Y-%m-%d %H:%M:%S.%f")
timeStamp = float(time.mktime(timeArray))
start = timeStamp
index = 0
for row in file:

    if isFirstrow:
        timewindow.append([])
        timewindow[index].append(firstrow)
        isFirstrow = False

    timeArray = time.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    end = timeStamp

    if timeArray.tm_hour > timing:
        print(str(timeArray.tm_hour) + "o'clock")
        timing = timing + 1
    elif timeArray.tm_hour < 0:
        continue
    elif timeArray.tm_hour >= 6:
        writer = csv.writer(open(filepath_write, 'w', newline=''))
        for eachwindow in timewindow:
            for eachflow in eachwindow:
                if eachflow[12] != "normal":
                    writer.writerow(eachflow)
        exit(0)
    timewindow[index].append(row)

    if end - start >= 120:

        start = end
        timewindow.append([])
        index = index + 1
