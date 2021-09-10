# this one is for simple experiment using the method proposed by Snort
# limit the amount of IP address and ports sent by a source host.

# alarm the supervisor if the count breaks the threshold.

import pandas as pd
import numpy as np
import time


class Detect_Unit(object):

    def __init__(self, sip, dip=[], dpt=[], reported=False):
        self.sip = sip
        self.dip = dip
        self.dpt = dpt
        self.reported = reported

    def setReported(self, reported):
        self.reported = reported

    def isReported(self):
        return self.reported

    def getSip(self):
        return self.sip

    def setSip(self, sip):
        self.sip = sip

    def count_ip(self):
        return len(self.dip)

    def count_pt(self):
        return len(self.dpt)

    def check_ip(self, testIP):
        if testIP not in self.dip:
            self.dip.append(testIP)

    def check_pt(self, testPt):
        if testPt not in self.dpt:
            self.dpt.append(testPt)


def detect(data, start, end):
    # detect abnormal data between start/end index of data.
    detect_count = 0
    wrong_count = 0
    duration = data[start:end]
    host = []
    i = 0
    while i < duration['Source IP'].size:
        isnew = True
        j = 0
        while j < len(host):
            if host[j].getSip() == duration['Source IP'].get(i):
                host[j].check_ip(duration['Destination IP'].get(i))
                host[j].check_pt(duration['Destination Port'].get(i))
                if host[j].count_pt() > 70 or host[j].count_ip() > 70:
                    if str(duration['Label'].get(i)) == "Syn":
                        detect_count = detect_count + 1
                    if str(duration['Label'].get(i)) == "BENIGN":
                        wrong_count = wrong_count + 1
                    if not host[j].isReported():
                        print("Abnormal refers to source ip:" + str(host[j].getSip()))
                        host[j].setReported(reported=True)
                isnew = False
            j = j + 1
        if isnew:
            new = Detect_Unit(sip=duration['Source IP'].get(i))
            new.check_ip(duration['Destination IP'].get(i))
            new.check_pt(duration['Destination Port'].get(i))
            host.append(new)
        i = i + 1

    return detect_count, wrong_count


data = pd.read_csv("D:\Python\Python37\myexperiment\portScanningDetection\Syn_dataset.csv", low_memory=False)
arr = pd.array(data['Timestamp'])
time_data = []
for i in range(0, len(arr)):
    timeArray = time.strptime("2021:3:8:20:" + arr[i][:-2], "%Y:%m:%d:%H:%M:%S")
    timeStamp = int(time.mktime(timeArray))
    time_data.append(timeStamp)
data['Timestamp'] = time_data
data = data.sort_values(by=['Timestamp'])
source_ip = data['Source IP']
i = 0
ips=[]
while i < len(source_ip):
    ips.append(str(source_ip[i]))
    i = i + 1
data['Source IP'] = ips

# dataframe = pd.DataFrame(data)
# 将DataFrame存储为csv,index表示是否显示行名，default=True
# dataframe.to_csv("test-3-9.csv",index=True,sep=',')
abnormal_count = 0
benign_count = 0
for i in data['Label']:
    if str(i) == "Syn":
        abnormal_count = abnormal_count + 1
    if str(i) == "BENIGN":
        benign_count = benign_count + 1

arr = data['Timestamp']
i = 0
start = i
detect_count = 0
wrong_count = 0
while i < data['Timestamp'].size:
    if time_data[i] - time_data[start] >= 30:
        (d, w) = detect(data, start, i)
        detect_count = detect_count + d
        wrong_count = wrong_count + w
        start = i + 1
        i = i + 1
        continue
    i = i + 1
print("abnormal count:" + str(abnormal_count))
print("benign count:" + str(benign_count))
print("right detected package:" + str(detect_count))
print("wrong detected package:" + str(wrong_count))
print("wrong detect percentage:" + str(wrong_count / benign_count))
print("right detect percentage:" + str(detect_count / abnormal_count))
