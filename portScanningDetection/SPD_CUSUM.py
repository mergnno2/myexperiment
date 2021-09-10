# this python file intends to copy the experiment proposed by Shaobo Xue
# the experiment refers to the paper:"基于持续增量模型的低速端口扫描检测算法"
# the main purpose of this experiment is to verify the precision of the algorithm which is
# mentioned in the above paper. Plus, some deficiency of this algorithm should be reveal
# during this experiment(such as some special slow port scan were not detected under the
# purposed algorithm).


import pandas as pd
import time
import numpy as np
import csv


class Host(object):
    def __init__(self, ip, pt):
        self.ip = ip
        self.pt = []
        self.pt.append(pt)


class Detect_Unit(object):

    def __init__(self, ip, dpt, dip):
        self.ip = ip
        self.dip = []
        self.dpt = []
        self.dip.append(dip)
        self.dpt.append(dpt)

        self.cusum_x1 = 0
        self.cusum_x2 = 0

        self.alarm = False

        self.live = True

        self.destination = []

        self.x1 = []
        self.x2 = []
        # self.x1.append(0)
        # self.x2.append(0)

    def similarity(self, host1, host2):
        summery = 0
        i = 0
        while i < len(host1.pt):
            if host1.pt[i] in host2.pt:
                summery = summery + 1
            i = i + 1
        m = len(host1.pt)
        n = len(host2.pt)
        if m < n:
            m = n
        return summery / m

    def calculateX2(self):
        if len(self.destination) <= 1:
            return 0
        sum = 0
        i = j = k = 0
        while i < len(self.destination):
            j = i + 1
            while j < len(self.destination):
                sum = sum + self.similarity(host1=self.destination[i], host2=self.destination[j])
                k = k + 1
                j = j + 1
            i = i + 1

        return sum / k

    def addDestination(self, dip, dpt):
        if len(self.destination) == 0:
            self.destination.append(Host(dip, dpt))
            return
        else:
            j = 0
            isNew = True
            while j < len(self.destination):
                if dip == self.destination[j].ip:
                    if dpt not in self.destination[j].pt:
                        self.destination[j].pt.append(dpt)
                    isNew = False
                    break
                j = j + 1
            if isNew:
                self.destination.append(Host(dip, dpt))
        return

    def addDip(self, dip):
        if dip not in self.dip:
            self.dip.append(dip)

    def addDpt(self, dpt):
        if dpt not in self.dpt:
            self.dpt.append(dpt)


def calculate_precision(timewindow, group):
    abnormal_count = 0
    abnormal_right = 0
    normal_count = 0
    normal_wrong = 0

    present = len(timewindow) - 1

    i = 0
    while i < len(timewindow[present]):
        if timewindow[present][i][12] != "normal":
            abnormal_count = abnormal_count + 1
            j = 0
            while j < len(group):
                if group[j].alarm:
                    if timewindow[present][i][5] == group[j].ip:
                        abnormal_right = abnormal_right + 1
                        break
                    if timewindow[present][i][3] == group[j].ip:
                        abnormal_right = abnormal_right + 1
                        break
                j = j + 1

        if timewindow[present][i][12] == "normal":
            normal_count = normal_count + 1

            j = 0
            while j < len(group):
                if group[j].alarm:
                    if timewindow[present][i][3] == group[j].ip:
                        '''print("--------------")
                        print(timewindow[present][i])
                        print(present,
                              i,
                              group[j].ip,
                              group[j].dip,
                              len(group[j].destination),
                              group[j].cusum_x1,
                              group[j].cusum_x2,
                              group[j].x1,
                              group[j].x2)
                        print("--------------")'''
                        normal_wrong = normal_wrong + 1
                        break

                    if timewindow[present][i][5] == group[j].ip:
                        '''print("--------------")
                        print(timewindow[present][i])
                        print(present,
                              i,
                              group[j].ip,
                              group[j].dip,
                              len(group[j].destination),
                              group[j].cusum_x1,
                              group[j].cusum_x2,
                              group[j].x1,
                              group[j].x2)
                        print("--------------")'''
                        normal_wrong = normal_wrong + 1
                        break
                j = j + 1
        i = i + 1

    return abnormal_count, abnormal_right, normal_count, normal_wrong


def predict(series):
    value = 0
    n = len(series)
    last = value
    i = 1
    while i < n:
        value = ((1 - (1 / i)) * last) + ((1 / i) * series[i])
        last = value
        i = i + 1
    return value


def cumulative_sum(group):
    if len(group) == 0:
        return
    else:
        j = 0
        while j < len(group):
            length = len(group[j].x1)
            yn = group[j].x1[length - 1] - predict(group[j].x1)
            m = 0
            n = group[j].cusum_x1 + yn
            if m > n:
                k = m
            else:
                k = n
            group[j].cusum_x1 = k

            length = len(group[j].x2)
            yn = group[j].x2[length - 1] - predict(group[j].x2)
            m = 0
            n = group[j].cusum_x2 + yn
            if m > n:
                k = m
            else:
                k = n
            group[j].cusum_x2 = k

            if group[j].cusum_x1 > threshold_x1 and group[j].cusum_x2 > threshold_x2:
                group[j].alarm = True
                # print(group[j].x1,group[j].x2)
            j = j + 1

    return


def create_statistic(group):
    if len(group) == 0:
        return
    else:
        j = 0
        while j < len(group):
            # print(group[j].x1,group[j].x2)
            if group[j].live:
                if (len(group[j].dip) / len(group[j].dpt)) > (len(group[j].dpt) / len(group[j].dip)):
                    k = (len(group[j].dip) / len(group[j].dpt))
                else:
                    k = (len(group[j].dpt) / len(group[j].dip))
                group[j].x1.append(k)
                group[j].x2.append(group[j].calculateX2())
            else:
                group[j].x1.append(-200)
                group[j].x2.append(-200)
            j = j + 1

    return


def mark_destination(timewindow, group):
    present = len(timewindow) - 1

    i = 0
    while i < len(timewindow[present]):
        j = 0
        while j < len(group):
            if group[j].ip == timewindow[present][i][3]:
                group[j].addDestination(dip=timewindow[present][i][5],
                                        dpt=timewindow[present][i][6])
            j = j + 1
        i = i + 1

    return


def mark_source_ip(timewindow, group):
    present = len(timewindow) - 1

    j = 0
    while j < len(group):
        group[j].dip.clear()
        group[j].dpt.clear()
        group[j].destination.clear()
        group[j].live = True
        j = j + 1

    i = 0
    while i < len(timewindow[present]):
        j = 0
        while j < len(group):
            if group[j].ip == timewindow[present][i][3] or group[j].ip == timewindow[present][i][5]:
                if group[j].alarm:
                    timewindow[present].__delitem__(i)
                    i = i - 1
                    break
            j = j + 1
        i = i + 1

    i = 0
    while i < len(timewindow[present]):
        isNew = True
        j = 0
        while j < len(group):
            if group[j].ip == timewindow[present][i][3]:
                group[j].addDip(dip=timewindow[present][i][5])
                group[j].addDpt(dpt=timewindow[present][i][6])
                isNew = False
                break
            j = j + 1
        if isNew:
            new = Detect_Unit(ip=timewindow[present][i][3],
                              dip=timewindow[present][i][5],
                              dpt=timewindow[present][i][6])
            group.append(new)
        i = i + 1

    j = 0
    while j < len(group):
        if len(group[j].dip) == 0 or len(group[j].dpt) == 0:
            group[j].live = False
        j = j + 1

    return


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"

# open the original csv data file
file = csv.reader(open(filepath, 'r'))

# timewindow contains five[which is given by windownum below and the specific number is decided by
# the method given in paper] item and each item is refers to 2 min flow data
timewindow = []
# timing is used to print the timestamp of flow data which is under the present calculation.
timing = 0
threshold_x1 = 0
threshold_x2 = 0

totaldetect = 0
rightdetect = 0
normaldetect = 0
wrongdetect = 0

group = []
# handle the first and second row
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
        print(str(timeArray.tm_hour) + "AM")
        timing = timing + 1
    elif timeArray.tm_hour < 0:
        continue
    elif timeArray.tm_hour >= 13:
        print("considered abnormal(actually abnormal):" + str(rightdetect) + "\ttotal abnormal:" + str(totaldetect))
        print("considered abnormal(actually abnormal)/total abnormal:" + str(rightdetect / totaldetect))
        print("considered abnormal(actually normal):" + str(wrongdetect) + "\ttotal normal:" + str(normaldetect))
        print("considered abnormal(actually normal)/total normal:" + str(wrongdetect / normaldetect))
        exit(0)

    timewindow[index].append(row)

    if end - start > 180:
        mark_source_ip(timewindow=timewindow, group=group)
        mark_destination(timewindow=timewindow, group=group)
        create_statistic(group=group)
        cumulative_sum(group=group)
        (t, r, n, w) = calculate_precision(timewindow=timewindow, group=group)
        totaldetect = totaldetect + t
        rightdetect = rightdetect + r
        normaldetect = normaldetect + n
        wrongdetect = wrongdetect + w

        start = end
        timewindow.append([])
        index = index + 1
