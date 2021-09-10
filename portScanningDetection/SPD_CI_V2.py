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


class Dpt(object):

    def __init__(self, dpt):
        self.dpt = dpt
        self.count = 1


class Dip(object):

    def __init__(self, dip):
        self.dip = dip
        self.count = 1


class Detect_Unit_Vertical(object):

    def __init__(self, sip, dpt, dip, windowalarm=False):
        self.sip = sip
        self.dip = dip
        self.dpt = []
        self.dpt.append(Dpt(dpt))
        self.windowalarm = windowalarm
        self.windowdata = []
        self.hasNewDpt = False
        self.dpt_flush = []
        self.firstSeenWindow = 0
        self.lastSeenWindow = 0
        self.entropy = 0

    def setLastSeenWindow(self, lastSeenWindow):
        self.lastSeenWindow = lastSeenWindow

    def getLastSeenWindow(self):
        return self.lastSeenWindow

    def setFirstSeenWindow(self, firstSeenWindow):
        self.firstSeenWindow = firstSeenWindow

    def getFirstSeenWindow(self):
        return self.firstSeenWindow

    def addDpt(self, dpt):
        i = 0
        isNew = True
        while i < len(self.dpt):
            if self.dpt[i].dpt == dpt:
                self.dpt[i].count = self.dpt[i].count + 1
                isNew = False
            i = i + 1
        if isNew:
            self.dpt.append(Dpt(dpt))

    def flush(self, dpt):
        i = 0
        isNew = True
        while i < len(self.dpt_flush):
            if self.dpt_flush[i].dpt == dpt:
                self.dpt_flush[i].count = self.dpt_flush[i].count + 1
                isNew = False
            i = i + 1
        if isNew:
            self.dpt_flush.append(Dpt(dpt))

    def setWindowalarm(self, windowalarm=True):
        self.windowalarm = windowalarm

    def containsDpt(self, dpt):
        i = 0
        while i < len(self.dpt):
            if self.dpt[i].dpt == dpt:
                return True
            i = i + 1
        return False


class Detect_Unit_Horizontal(object):

    def __init__(self, sip, dpt, dip, windowalarm=False):
        self.sip = sip
        self.dpt = dpt
        self.dip = []
        self.dip.append(Dip(dip))
        self.windowalarm = windowalarm
        self.hasNewDip = False
        self.dip_flush = []
        self.firstSeenWindow = 0
        self.lastSeenWindow = 0
        self.entropy = 0

    def setLastSeenWindow(self, lastSeenWindow):
        self.lastSeenWindow = lastSeenWindow

    def getLastSeenWindow(self):
        return self.lastSeenWindow

    def setFirstSeenWindow(self, firstSeenWindow):
        self.firstSeenWindow = firstSeenWindow

    def getFirstSeenWindow(self):
        return self.firstSeenWindow

    def addDip(self, dip):
        i = 0
        isNew = True
        while i < len(self.dip):
            if self.dip[i].dip == dip:
                self.dip[i].count = self.dip[i].count + 1
                isNew = False
            i = i + 1
        if isNew:
            self.dip.append(Dip(dip))

    def flush(self, dip):
        i = 0
        isNew = True
        while i < len(self.dip_flush):
            if self.dip_flush[i].dip == dip:
                self.dip_flush[i].count = self.dip_flush[i].count + 1
                isNew = False
            i = i + 1
        if isNew:
            self.dip_flush.append(Dip(dip))

    def setWindowalarm(self, windowalarm=True):
        self.windowalarm = windowalarm

    def containsDip(self, dip):
        i = 0
        while i < len(self.dip):
            if self.dip[i].dip == dip:
                return True
            i = i + 1
        return False


def calculate_entropy_horizontal(timewindow, connection):
    startwindow = connection.getFirstSeenWindow()
    endwindow = connection.getLastSeenWindow()
    totalflowcount = 0
    connectionflowcount = 0
    connectionDipcount = 0
    i = startwindow
    while i <= endwindow:
        totalflowcount = totalflowcount + len(timewindow[i])
        j = 0
        while j < len(timewindow[i]):
            if timewindow[i][j][3] == connection.sip and timewindow[i][j][6] == connection.dpt:
                connectionflowcount = connectionflowcount + 1
            j = j + 1
        i = i + 1
    dipentropy = float(0)
    i = 0
    while i < len(connection.dip):
        connectionDipcount = connectionDipcount + connection.dip[i].count
        i = i + 1
    i = 0
    while i < len(connection.dip):
        per = float(connection.dip[i].count / connectionDipcount)
        dipentropy = dipentropy + (per * -np.math.log(per))
        i = i + 1

    # print(dipentropy * (connectionflowcount / totalflowcount))
    return dipentropy  # * (connectionflowcount / totalflowcount)


def calculate_entropy_vertical(timewindow, connection):
    startwindow = connection.getFirstSeenWindow()
    endwindow = connection.getLastSeenWindow()
    totalflowcount = 0
    connectionflowcount = 0
    connectionDptcount = 0
    i = startwindow
    while i <= endwindow:
        totalflowcount = totalflowcount + len(timewindow[i])
        j = 0
        while j < len(timewindow[i]):
            if timewindow[i][j][3] == connection.sip and timewindow[i][j][5] == connection.dip:
                connectionflowcount = connectionflowcount + 1
            j = j + 1
        i = i + 1
    dptentropy = 0
    i = 0
    while i < len(connection.dpt):
        connectionDptcount = connectionDptcount + connection.dpt[i].count
        i = i + 1
    i = 0
    while i < len(connection.dpt):
        per = float(connection.dpt[i].count / connectionDptcount)
        dptentropy = dptentropy + (per * -np.math.log(per))
        i = i + 1
    #for x in connection.dpt:
        #if x.dpt=="   443" and connection.sip=="192.168.220.16":
            #print(dptentropy)
    return dptentropy  # * (connectionflowcount / totalflowcount)


def check_connection_set(timewindow, group_horizontal, group_vertical):
    t_detect = 0  # total number of abnormal( sometimes just attacker) flow data
    r_detect = 0  # total number of right detected flow data
    normal_detect = 0
    wrong_detect = 0

    j = 0
    while j < len(group_horizontal):
        group_horizontal[j].hasNewDip = False
        #group_horizontal[j].windowalarm = False
        group_horizontal[j].entropy = 0
        j = j + 1
    j = 0
    while j < len(group_vertical):
        group_vertical[j].hasNewDpt = False
        #group_vertical[j].windowalarm = False
        group_vertical[j].entropy = 0
        j = j + 1

    index = len(timewindow) - 1
    i = 0
    while i < len(timewindow[index]):
        isNew = True
        j = 0
        while j < len(group_horizontal):
            if group_horizontal[j].sip == timewindow[index][i][3] and \
                    group_horizontal[j].dpt == timewindow[index][i][6]:
                # if this dip is new for this sip-dpt connection
                if not group_horizontal[j].containsDip(dip=timewindow[index][i][5]):
                    group_horizontal[j].hasNewDip = True
                else:
                    group_horizontal[j].flush(timewindow[index][i][5])
                group_horizontal[j].addDip(timewindow[index][i][5])
                isNew = False
                group_horizontal[j].setLastSeenWindow(lastSeenWindow=index)
                break
            j = j + 1
        if isNew:
            new = Detect_Unit_Horizontal(sip=timewindow[index][i][3],
                                         dpt=timewindow[index][i][6],
                                         dip=timewindow[index][i][5])
            new.setLastSeenWindow(lastSeenWindow=index)
            new.setFirstSeenWindow(firstSeenWindow=index)
            new.hasNewDip = True
            group_horizontal.append(new)

        isNew = True
        j = 0
        while j < len(group_vertical):
            if group_vertical[j].sip == timewindow[index][i][3] and \
                    group_vertical[j].dip == timewindow[index][i][5]:
                # if this dip is new for this sip-dpt connection
                if not group_vertical[j].containsDpt(dpt=timewindow[index][i][6]):
                    group_vertical[j].hasNewDpt = True
                else:
                    group_vertical[j].flush(timewindow[index][i][6])
                group_vertical[j].addDpt(timewindow[index][i][6])
                isNew = False
                group_vertical[j].setLastSeenWindow(lastSeenWindow=index)
                break
            j = j + 1
        if isNew:
            new = Detect_Unit_Vertical(sip=timewindow[index][i][3],
                                       dpt=timewindow[index][i][6],
                                       dip=timewindow[index][i][5])
            new.setLastSeenWindow(lastSeenWindow=index)
            new.setFirstSeenWindow(firstSeenWindow=index)
            new.hasNewDpt = True
            group_vertical.append(new)
        i = i + 1

    j = 0
    while j < len(group_horizontal):
        # if len(group_horizontal[j].dip) > 3:
        # print(group_horizontal[j].getLastSeenWindow(),
        # group_horizontal[j].getFirstSeenWindow(),
        # len(group_horizontal[j].dip))
        if group_horizontal[j].hasNewDip:
            group_horizontal[j].dip_flush.clear()
        else:
            if index - group_horizontal[j].getLastSeenWindow() > 0:
                # if some connection is not shown in 3*2min continual time window then erase it
                group_horizontal[j].setFirstSeenWindow(firstSeenWindow=index)
                group_horizontal[j].setLastSeenWindow(lastSeenWindow=index)
                group_horizontal[j].dip.clear()
                group_horizontal[j].dip = group_horizontal[j].dip_flush
                group_horizontal[j].dip_flush.clear()
                j = j + 1
                continue
            if int(group_horizontal[j].getLastSeenWindow() - group_horizontal[j].getFirstSeenWindow()) > windownum:
                # this connection suit with the condition of continual 5*2min time window
                group_horizontal[j].entropy = calculate_entropy_horizontal(timewindow=timewindow,
                                                                           connection=group_horizontal[j])
                if group_horizontal[j].entropy > threshold:
                    group_horizontal[j].setWindowalarm(True)
        j = j + 1
    j = 0
    while j < len(group_vertical):
        if group_vertical[j].hasNewDpt:
            group_vertical[j].dpt_flush.clear()
        else:
            if index - group_vertical[j].getLastSeenWindow() > 0:
                # if some connection is not shown in 10*2min continual time window then erase it
                group_vertical[j].setFirstSeenWindow(firstSeenWindow=index)
                group_vertical[j].setLastSeenWindow(lastSeenWindow=index)
                group_vertical[j].dpt.clear()
                group_vertical[j].dpt = group_vertical[j].dpt_flush
                group_vertical[j].dpt_flush.clear()
                j = j + 1
                continue
            if int(group_vertical[j].getLastSeenWindow() - group_vertical[j].getFirstSeenWindow()) > windownum:
                # this connection suit with the condition of continual 5*2min time window
                group_vertical[j].entropy = calculate_entropy_vertical(timewindow=timewindow,
                                                                       connection=group_vertical[j])
                if group_vertical[j].entropy > threshold:
                    group_vertical[j].setWindowalarm(True)

        j = j + 1

    # calculate the precision of the algorithm
    i = 0
    while i < len(timewindow[index]):
        # if the flow is labelled as abnormal data, calculate the total detect number
        if timewindow[index][i][12] != "normal":
            t_detect = t_detect + 1
            # check if the suspicious sip-dpt refers to real abnormal data
            # in other words, calculate precision of horizontal port scanning detection
            isVerticalDetected = False
            k = 0
            while k < len(group_vertical):
                # if this combination shows in both five 2min windows, check the sip and dip if
                # these two parameters are the same as timewindow[0][j]'s sip and dip, while
                # timewindow[0][j] is abnormal data because of its labelling.
                if group_vertical[k].windowalarm:
                    if group_vertical[k].sip == timewindow[index][i][3] \
                            and group_vertical[k].dip == timewindow[index][i][5]:
                        r_detect = r_detect + 1
                        isVerticalDetected = True
                        break
                k = k + 1
            if isVerticalDetected:
                i = i + 1
                continue
            k = 0
            isHorizontalDetected = False
            while k < len(group_horizontal):
                # if this combination shows in both five 2min windows, check the sip and dip if
                # these two parameters are the same as timewindow[0][j]'s sip and dip, while
                # timewindow[0][j] is abnormal data because of its labelling.
                if group_horizontal[k].windowalarm:
                    if group_horizontal[k].sip == timewindow[index][i][3] \
                            and group_horizontal[k].dpt == timewindow[index][i][6]:
                        r_detect = r_detect + 1
                        isHorizontalDetected = True
                        break
                k = k + 1
            #if not isVerticalDetected:
                #if not isHorizontalDetected:
                    #print(timewindow[index][i])
        elif timewindow[index][i][12] == "normal":
            normal_detect = normal_detect + 1
            # check if the suspicious sip-dpt refers to real abnormal data
            # in other words, calculate precision of horizontal port scanning detection
            isVerticalDetected = False
            k = 0
            while k < len(group_vertical):
                # if this combination shows in both five 2min windows, check the sip and dip if
                # these two parameters are the same as timewindow[0][j]'s sip and dip, while
                # timewindow[0][j] is abnormal data because of its labelling.
                if group_vertical[k].windowalarm:
                    if group_vertical[k].sip == timewindow[index][i][3] \
                            and group_vertical[k].dip == timewindow[index][i][5]:
                        #print(timewindow[index][i])
                        wrong_detect = wrong_detect + 1
                        isVerticalDetected = True
                        break
                k = k + 1
            if isVerticalDetected:
                i = i + 1
                continue
            k = 0
            isHorizontalDetected = False
            while k < len(group_horizontal):
                # if this combination shows in both five 2min windows, check the sip and dip if
                # these two parameters are the same as timewindow[0][j]'s sip and dip, while
                # timewindow[0][j] is abnormal data because of its labelling.
                if group_horizontal[k].windowalarm:
                    if group_horizontal[k].sip == timewindow[index][i][3] \
                            and group_horizontal[k].dpt == timewindow[index][i][6]:
                        wrong_detect = wrong_detect + 1
                        #print(timewindow[index][i])
                        isHorizontalDetected = True
                        break
                k = k + 1
        i = i + 1

    return t_detect, r_detect, normal_detect, wrong_detect


filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"

# open the original csv data file
file = csv.reader(open(filepath, 'r'))

# timewindow contains five[which is given by windownum below and the specific number is decided by
# the method given in paper] item and each item is refers to 2 min flow data
timewindow = []
windownum = 5
threshold = 1.1
# following attribute is used to calculate the precision of the proposed method.
totaldetect = 0
rightdetect = 0
normaldetect = 0
wrongdetect = 0
# timing is used to print the timestamp of flow data which is under the present calculation.
timing = 0
# group is used to store every single sip-dpt connection and erase some item from it. When some connection does
# not shown in next 2 min time window
group_horizontal = []
group_vertical = []
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
    elif timeArray.tm_hour >= 3:
        print("considered abnormal(actually abnormal):" + str(rightdetect) + "\ttotal abnormal:" + str(totaldetect))
        print("considered abnormal(actually abnormal)/total abnormal:" + str(rightdetect / totaldetect))
        print("considered abnormal(actually normal):" + str(wrongdetect) + "\ttotal normal:" + str(normaldetect))
        print("considered abnormal(actually normal)/total normal:" + str(wrongdetect / normaldetect))
        exit(0)

    timewindow[index].append(row)

    if end - start > 120:
        # to update the suspicious sip-dpt connection set.
        (t, r, n, w) = check_connection_set(timewindow=timewindow,
                                            group_horizontal=group_horizontal,
                                            group_vertical=group_vertical)
        # print(str(len(group_vertical))+"\t\t\t"+str(len(group_horizontal)))

        # to check if the suspicious sip-dpt is considered as abnormal according to algorithm based on entropy.
        # check_suspicious(group=group)

        totaldetect = totaldetect + t
        rightdetect = rightdetect + r
        normaldetect = normaldetect + n
        wrongdetect = wrongdetect + w
        start = end
        timewindow.append([])
        index = index + 1
