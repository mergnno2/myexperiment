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

class Detect_Unit_Vertical(object):

    def __init__(self, sip, dip, dpt, windowalarm=False):
        self.sip = sip
        self.dip = dip
        self.dpt = []
        self.dpt.append(dpt)
        self.windowalarm = windowalarm

    def getSip(self):
        return self.sip

    def setSip(self, sip):
        self.sip = sip

    def getDip(self):
        return self.dip

    def setDip(self, dip):
        self.dip = dip

    def getDptSize(self):
        return len(self.dpt)

    def setWindownum(self, windownum):
        self.windownum = windownum

    def getWindownum(self):
        return self.windownum

    def updateWindowcount(self):
        self.windowcount = self.windowcount + 1

    def getWindowcount(self):
        return self.windowcount

    def searchDpt(self, dpt):
        if dpt in self.dpt:
            return True
        else:
            return False

    def setWindowalarm(self, windowalarm):
        self.windowalarm = windowalarm

    def contains(self, sip, dip, dpt):
        if (sip == self.sip) and (dip == self.dip):
            if dpt not in self.dpt:
                self.dpt.append(dpt)
            return True
        else:
            return False


class Detect_Unit_Horizontal(object):

    def __init__(self, sip, dpt, dip, windowalarm=False):
        self.sip = sip
        self.dpt = dpt
        self.dip = []
        self.dip.append(dip)
        self.windowalarm = windowalarm

    def getSip(self):
        return self.sip

    def setSip(self, sip):
        self.sip = sip

    def getDpt(self):
        return self.dpt

    def setDpt(self, dpt):
        self.dpt = dpt

    def getDipSize(self):
        return len(self.dip)

    def searchDip(self, dip):
        if dip in self.dip:
            return True
        else:
            return False

    def setWindowalarm(self, windowalarm):
        self.windowalarm = windowalarm

    def contains(self, sip, dpt, dip):
        if (sip == self.sip) and (dpt == self.dpt):
            if dip not in self.dip:
                self.dip.append(dip)
            return True
        else:
            return False


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
'''
def analyze_vertical(datagroup, group):
    # since the datagroup refers to a set of flow data captured in 2 minute on the router
    # detect(datagroup) is used to detect the abnormal flow data that hidden in datagroup
    # using Continual Increasing Model method
    if len(datagroup) == 0:
        return 0
    for row in datagroup:
        isNew = True
        j = 0
        while j < len(group):
            if group[j].contains(sip=str(row[3]), dpt=str(row[6]), dip=str(row[5])):
                isNew = False
                break
            j = j + 1
        if isNew:
            new = Detect_Unit_Vertical(sip=str(row[3]), dpt=str(row[6]), dip=str(row[5]))
            # print(row[3], '\t\t\t' + row[6] + '\t\t\t', row[5])
            group.append(new)

    return 1
'''

'''
def analyze_horizontal(datagroup, group):
    # since the datagroup refers to a set of flow data captured in 2 minute on the router
    # detect(datagroup) is used to detect the abnormal flow data that hidden in datagroup
    # using Continual Increasing Model method
    if len(datagroup) == 0:
        return 0
    for row in datagroup:
        isNew = True
        j = 0
        while j < len(group):
            if group[j].contains(sip=str(row[3]), dpt=str(row[6]), dip=str(row[5])):
                isNew = False
                break
            j = j + 1
        if isNew:
            new = Detect_Unit_Horizontal(sip=str(row[3]), dpt=str(row[6]), dip=str(row[5]))
            # print(row[3], '\t\t\t' + row[6] + '\t\t\t', row[5])
            group.append(new)

    return 1
'''

# check_suspicious is used to find suspicious sip-dpt in timewindow that is refers to 10 min flow data.
def check_suspicious(timewindow):
    t_detect = 0  # total number of abnormal( sometimes just attacker) flow data
    r_detect = 0  # total number of right detected flow data
    group_horizontal = []
    group_vertical = []

    # record every single sip-dpt type connection in five 2-min flow data
    groupindex = 0
    while groupindex < len(timewindow):
        flowindex = 0
        while flowindex < len(timewindow[groupindex]):
            isNew = True
            j = 0
            while j < len(group_horizontal):
                if group_horizontal[j].contains(sip=str(timewindow[groupindex][flowindex][3]),
                                     dpt=str(timewindow[groupindex][flowindex][6]),
                                     dip=str(timewindow[groupindex][flowindex][5])):
                    isNew = False
                    break
                j = j + 1
            if isNew:
                new = Detect_Unit_Horizontal(sip=str(timewindow[groupindex][flowindex][3]),
                                             dpt=str(timewindow[groupindex][flowindex][6]),
                                             dip=str(timewindow[groupindex][flowindex][5]))
                group_horizontal.append(new)
            flowindex = flowindex + 1
        groupindex = groupindex + 1

    # mark the suspicious sip-dpt combination which is recorded above
    for eachcombination in group_horizontal:
        i = 0
        count = 0
        while i < len(timewindow):
            j = 0
            while j < len(timewindow[i]):
                # timwindow[i][j] refers to number i of 2 min datagroup, and number j of flowdata in each 2 min datagroup
                if eachcombination.ip == timewindow[i][j][3] and eachcombination.dpt == timewindow[i][j][6]:
                    count = count + 1
                    break
                j = j + 1
            i = i + 1
        if count >= windownum-3:
            # if some combination shows in some 2 min windows ,mark this combination as alarmed.
            eachcombination.setWindowalarm(True)

    # record every single sip-dip type connection in five 2-min flow data
    groupindex = 0
    while groupindex < len(timewindow):
        flowindex = 0
        while flowindex < len(timewindow[groupindex]):
            isNew = True
            j = 0
            while j < len(group_vertical):
                if group_vertical[j].contains(sip=str(timewindow[groupindex][flowindex][3]),
                                                dpt=str(timewindow[groupindex][flowindex][6]),
                                                dip=str(timewindow[groupindex][flowindex][5])):
                    isNew = False
                    break
                j = j + 1
            if isNew:
                new = Detect_Unit_Vertical(sip=str(timewindow[groupindex][flowindex][3]),
                                             dpt=str(timewindow[groupindex][flowindex][6]),
                                             dip=str(timewindow[groupindex][flowindex][5]))
                group_vertical.append(new)
            flowindex = flowindex + 1
        groupindex = groupindex + 1

    # mark the suspicious sip-dip combination which is recorded above
    for eachcombination in group_vertical:
        i = 0
        count = 0
        while i < len(timewindow):
            j = 0
            while j < len(timewindow[i]):
                # timwindow[i][j] refers to number i of 2 min datagroup, and number j of flowdata in each 2 min datagroup
                if eachcombination.ip == timewindow[i][j][3] and eachcombination.dip == timewindow[i][j][5]:
                    count = count + 1
                    break
                j = j + 1
            i = i + 1
        if count >= windownum-3:
            # if some combination shows in some 2 min windows ,mark this combination as alarmed.
            eachcombination.setWindowalarm(True)

    j = 0
    while j < len(timewindow[0]):
        # if the flow is labelled as abnormal data, calculate the total detect number
        if timewindow[0][j][12] == "attacker":
            t_detect = t_detect + 1
            # check if the suspicious sip-dip refers to real abnormal data
            # in other words, calculate precision of vertical port scanning detection
            isVerticalDetected=False
            k = 0
            while k < len(group_vertical):
                # if this combination shows in both five 2min windows, check the sip and dpt if
                # these two parameters are the same as timewindow[0][j]'s sip and dpt, while
                # timewindow[0][j] is abnormal data because of its labelling.
                if group_vertical[k].windowalarm:
                    if group_vertical[k].sip == timewindow[0][j][3] \
                            and group_vertical[k].dip == timewindow[0][j][5]:
                        r_detect = r_detect + 1
                        isVerticalDetected=True
                        break
                k = k + 1
            # check if the suspicious sip-dpt refers to real abnormal data
            # in other words, calculate precision of horizontal port scanning detection
            if isVerticalDetected:
                j = j + 1
                continue
            k = 0
            isHorizontalDetected=False
            while k < len(group_horizontal):
                # if this combination shows in both five 2min windows, check the sip and dip if
                # these two parameters are the same as timewindow[0][j]'s sip and dip, while
                # timewindow[0][j] is abnormal data because of its labelling.
                if group_horizontal[k].windowalarm:
                    if group_horizontal[k].sip == timewindow[0][j][3]\
                            and group_horizontal[k].dpt == timewindow[0][j][6]:
                        r_detect = r_detect + 1
                        isHorizontalDetected=True
                        break
                k = k + 1
            if not isVerticalDetected:
                if not isHorizontalDetected:
                    print(timewindow[0][j])
        j = j + 1

    group_vertical.clear()
    group_horizontal.clear()
    return t_detect, r_detect


# open the original csv data file
file = csv.reader(open(filepath, 'r'))

# timewindow contains five[which is given by windownum below and the specific number is decided by
# the method given in paper] item and each item is refers to 2 min flow data
timewindow = []
windownum = 6
# following attribute is used to calculate the precision of the proposed method.
totaldetect = 0
rightdetect = 0
# timing is used to print the timestamp of flow data which is under the present calculation.
timing = 0

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
    timewindow[index].append(row)



    if end - start > 120:
        start = end
        if index == windownum - 1:
            # for item in timewindow:
            #    print(item)
            # when finishing the analyze of five datagroup, try to find suspicious sip-dpt that
            # shows in both five datagroups.
            (t, r) = check_suspicious(timewindow=timewindow)
            totaldetect = totaldetect + t
            rightdetect = rightdetect + r
            k = 0
            while k < windownum - 1:
                timewindow[k] = timewindow[k + 1]
                k = k + 1
            timewindow.__delitem__(k)
            timewindow.append([])
        else:
            timewindow.append([])
            index = index + 1
    if timeArray.tm_hour > timing:
        print(timeArray.tm_hour)
        timing = timing + 1
    elif timeArray.tm_hour > 4:
        print("right:" + str(rightdetect) + "\ttotal:" + str(totaldetect))
        print("right/total:" + str(rightdetect / totaldetect))
        exit(0)

'''
    
    # datagroup contains 2 min data from the original csv file
    datagroup = []
    # handle the first and second row of the original data
    if isFirstrow:
        datagroup.append(firstrow)
        isFirstrow = False

    datagroup.append(row)
    timeArray = time.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    end = timeStamp

    if end - start > 120:
        start = end
        if len(timewindow) < windownum:
            timewindow.append(datagroup)
            print(timewindow[0])
        elif len(timewindow) == windownum:
            # for item in timewindow:
            #    print(item)
            # when finishing the analyze of five datagroup, try to find suspicious sip-dpt that
            # shows in both five datagroups.
            (t, r) = check_suspicious(timewindow=timewindow)
            totaldetect = totaldetect + t
            rightdetect = rightdetect + r
            k = 0
            while k < windownum - 1:
                timewindow[k] = timewindow[k + 1]
                k = k + 1
            timewindow[k] = datagroup
        # print(len(group))
        # if len(group) > 4000:

        datagroup.clear()'''

# origin=np.memmap(filepath,mode='r',dtype=(str,64))
# print(origin[1:5])

# data = pd.read_csv(filepath, low_memory=False)
# print("hello")
