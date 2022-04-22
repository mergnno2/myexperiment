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
flow_file = csv.reader(open(filepath, 'r'))
filepath_write = "D:\Python\Python37\myexperiment\only-67-68.csv"
flow_file_write = csv.writer(open(filepath_write, 'w', newline=""))

flow_data = []

timing = 0

stamps = []
ewma = []
per = []
alpha = 0.01
end = 0
start = 0
sum = 0
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
    if row[14] == "67" or row[14] == "68":
        flow_file_write.writerow(row)
