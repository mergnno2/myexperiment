import re

import pandas as pd
import time
import numpy as np
import csv


class Destination(object):
    def __init__(self, ip, count=1):
        self.ip = ip
        self.count = count


class Destination_Vertical(object):
    def __init__(self, pt, count=1):
        self.pt = pt
        self.count = count


class Horizontal(object):
    def __init__(self, sip, dpt, dip):
        self.sip = sip
        self.dpt = dpt
        self.destination = []
        self.destination.append(Destination(ip=dip, count=1))

        self.continual = 1
        self.continual_updated = True
        self.destination_updated = True

        self.entropy = 0

        self.isAbnormal = False

    def match(self, sip, dpt):
        if self.sip == sip and self.dpt == dpt:
            return True
        return False

    def upDateDip(self, dip):
        for item in self.destination:
            if item.ip == dip:
                item.count = item.count + 1
                return
        self.destination.append(Destination(ip=dip, count=1))
        self.destination_updated = True

    def upDateContinual(self):
        if not self.continual_updated:
            self.continual = self.continual + 1
            self.continual_updated = True

    def upDateEntropy(self):
        if len(self.destination) == 0:
            self.entropy = 0
            return
        total_count = 0
        for item in self.destination:
            total_count = total_count + item.count
        self.entropy = 0
        for item in self.destination:
            per = float(item.count / total_count)
            self.entropy = self.entropy + (per * -np.math.log(per))


class Vertical(object):
    def __init__(self, sip, dpt, dip):
        self.sip = sip
        self.dip = dip
        self.destination = []
        self.destination.append(Destination_Vertical(pt=dpt, count=1))

        self.continual = 1
        self.continual_updated = True
        self.destination_updated = True

        self.entropy = 0

        self.isAbnormal = False

    def match(self, sip, dip):
        if self.sip == sip and self.dip == dip:
            return True
        return False

    def upDateDpt(self, dpt):
        for item in self.destination:
            if item.pt == dpt:
                item.count = item.count + 1
                return
        self.destination.append(Destination_Vertical(pt=dpt, count=1))
        self.destination_updated = True

    def upDateContinual(self):
        if not self.continual_updated:
            self.continual = self.continual + 1
            self.continual_updated = True

    def upDateEntropy(self):
        if len(self.destination) == 0:
            self.entropy = 0
            return
        total_count = 0
        for item in self.destination:
            total_count = total_count + item.count
        self.entropy = 0
        for item in self.destination:
            per = float(item.count / total_count)
            self.entropy = self.entropy + (per * -np.math.log(per))


def normalizeEntropy(group):
    max = 0
    min = 0
    for connection in group:
        if max < connection.entropy:
            max = connection.entropy
        if min > connection.entropy:
            min = connection.entropy
    if max == 0:
        return
    _range = max - min
    for connection in group:
        connection.entropy = (connection.entropy - min) / _range


def markConnection_horizontal(timewindow, group_horizontal):
    for connection in group_horizontal:
        connection.continual_updated = False
        connection.isAbnormal = False
        connection.destination_updated = False

    i = 0
    while i < len(timewindow[index]):
        j = 0
        isNew = True
        while j < len(group_horizontal):
            if group_horizontal[j].match(sip=timewindow[index][i][3], dpt=timewindow[index][i][6]):
                group_horizontal[j].upDateContinual()
                group_horizontal[j].upDateDip(dip=timewindow[index][i][5])
                isNew = False
                break
            j = j + 1
        if isNew:
            new = Horizontal(sip=timewindow[index][i][3],
                             dpt=timewindow[index][i][6],
                             dip=timewindow[index][i][5])
            group_horizontal.append(new)
        i = i + 1
    return


def markConnection_vertical(timewindow, group_vertical):
    for connection in group_vertical:
        connection.continual_updated = False
        connection.isAbnormal = False
        connection.destination_updated = False

    i = 0
    while i < len(timewindow[index]):
        j = 0
        isNew = True
        while j < len(group_vertical):
            if group_vertical[j].match(sip=timewindow[index][i][3], dip=timewindow[index][i][5]):
                group_vertical[j].upDateContinual()
                group_vertical[j].upDateDpt(dpt=timewindow[index][i][6])
                isNew = False
                break
            j = j + 1
        if isNew:
            new = Vertical(sip=timewindow[index][i][3],
                           dpt=timewindow[index][i][6],
                           dip=timewindow[index][i][5])
            group_vertical.append(new)
        i = i + 1
    return


def calculateEntropy_horizontal(group_horizontal):
    j = 0
    while j < len(group_horizontal):
        if not group_horizontal[j].continual_updated:
            group_horizontal.__delitem__(j)
            continue
        else:
            if not group_horizontal[j].destination_updated:
                group_horizontal[j].destination.clear()
        if group_horizontal[j].continual >= windownum:
            group_horizontal[j].upDateEntropy()
        j = j + 1
    #normalizeEntropy(group_horizontal)
    j = 0
    while j < len(group_horizontal):
        if group_horizontal[j].entropy > threshold:
            group_horizontal[j].isAbnormal = True
        j = j + 1
    return


def calculateEntropy_vertical(group_vertical):
    j = 0
    while j < len(group_vertical):
        if not group_vertical[j].continual_updated:
            group_vertical.__delitem__(j)
            continue
        else:
            if not group_vertical[j].destination_updated:
                group_vertical[j].destination.clear()
        if group_vertical[j].continual >= windownum:
            group_vertical[j].upDateEntropy()
        j = j + 1
    #normalizeEntropy(group_vertical)
    j = 0
    while j < len(group_vertical):
        if group_vertical[j].entropy > threshold:
            group_vertical[j].isAbnormal = True
        j = j + 1
    return


def markAbnormal(timewindow, group_horizontal, group_vertical):
    for flow in timewindow[index]:
        j = 0
        isAbnormal = False
        # if flow[12] == "attacker":
        # print(flow)
        while j < len(group_horizontal):
            if group_horizontal[j].isAbnormal:
                if flow[3] == group_horizontal[j].sip and flow[6] == group_horizontal[j].dpt:
                    flow.append("abnormal")
                    #if flow[12] == "normal":
                        #print(flow)
                    isAbnormal = True
                    break
            j = j + 1
        if not isAbnormal:
            j = 0
            while j < len(group_vertical):
                if group_vertical[j].isAbnormal:
                    if flow[3] == group_vertical[j].sip and flow[5] == group_vertical[j].dip:
                        flow.append("abnormal")
                        #if flow[12] == "normal":
                            #print("vertical", flow)
                        isAbnormal = True
                        break
                j = j + 1
        if not isAbnormal:
            flow.append("normal")
    return


def calculate_precision(timewindow):
    rightdetect = 0
    wrongdetect = 0
    totalabnormal = 0
    totalnormal = 0
    for eachwindow in timewindow:
        i = 0
        while i < len(eachwindow):
            if eachwindow[i][-1] != "normal" and eachwindow[i][-1] != "abnormal":
                i = i + 1
                continue
            if eachwindow[i][12] == "normal":
                totalnormal = totalnormal + 1
            if eachwindow[i][12] != "normal":
                totalabnormal = totalabnormal + 1
            if eachwindow[i][12] != "normal" and eachwindow[i][-1] == "abnormal":
                rightdetect = rightdetect + 1
            if eachwindow[i][12] == "normal" and eachwindow[i][-1] == "abnormal":
                wrongdetect = wrongdetect + 1
            i = i + 1
    if totalnormal == 0 or totalabnormal == 0:
        return
    print("considered abnormal(actually abnormal):" + str(rightdetect) + "\ttotal abnormal:" + str(totalabnormal))
    print("considered abnormal(actually abnormal)/total abnormal:" + str(rightdetect / totalabnormal))
    print("considered abnormal(actually normal):" + str(wrongdetect) + "\ttotal normal:" + str(totalnormal))
    print("considered abnormal(actually normal)/total normal:" + str(wrongdetect / totalnormal))
    return


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
# open the original csv data file
file = csv.reader(open(filepath, 'r'))

timewindow = []
windownum = 5
threshold = 0.9

timing = 0

group_horizontal = []
group_vertical = []

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
    elif timeArray.tm_hour >=6:
        calculate_precision(timewindow=timewindow)
        exit(0)

    #if re.search("\.", row[3]) == None or re.search("\.", row[5]) == None or \
            #row[3] == "192.168.100.6" or row[5] == "192.168.100.6":
            #row[3] == "192.168.100.5" or row[5] == "192.168.100.5" or \
            #row[3] == "192.168.100.4" or row[5] == "192.168.100.4" or \
            #row[3] == "192.168.100.3" or row[5] == "192.168.100.3":
        #continue
    timewindow[index].append(row)

    if end - start >= 120:
        markConnection_horizontal(timewindow=timewindow, group_horizontal=group_horizontal)
        markConnection_vertical(timewindow=timewindow, group_vertical=group_vertical)
        calculateEntropy_horizontal(group_horizontal=group_horizontal)
        calculateEntropy_vertical(group_vertical=group_vertical)
        markAbnormal(timewindow=timewindow, group_horizontal=group_horizontal, group_vertical=group_vertical)

        start = end
        timewindow.append([])
        index = index + 1