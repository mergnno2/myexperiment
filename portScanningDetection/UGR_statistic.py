import re
import time

filepath = "D:/Python/Python37/myexperiment/portScanningDetection/UGR16/august.week1.csv"
file = open(filepath)

timing = 0


def check_suspicious(flow):
    # check one flow if it is a suspicious flow by checking the flags

    # return types:
    # 0 - not suspicious
    # 1 - RST error
    # 2 - ICMP error
    if re.search('F', flow[7]) is not None:
        return 0
    elif re.search('S', flow[7]) is not None:
        return 0
    elif re.search('U', flow[7]) is not None:
        return 0
    elif re.search('P', flow[7]) is not None:
        return 0
    elif re.search('R', flow[7]) is not None:
        return 1
    return 0

def print_timing(row_to_print_time):
    global timing
    timeArray = time.strptime(row_to_print_time[0], "%Y-%m-%d %H:%M:%S")

    if timing == 24 and timeArray.tm_hour == 0:
        timing = 0
    if timeArray.tm_hour >= timing:
        print("Month:", timeArray.tm_mon, "Day:", timeArray.tm_mday, ",", timing % 24, "o'clock")
        timing = timing + 1
    if timeArray.tm_hour == 9:
        return 2
    if timeArray.tm_hour < 8:
        return 1
    if timeArray.tm_hour == 8 and timeArray.tm_min<30:
        return 1
    return 0


next(file)
next(file)
next(file)
count=0
count_total = 0
count_abnormal = 0
flag=False

for r in file:
    row = r.split(',')
    if print_timing(row_to_print_time=row) == 1:
        continue
    if print_timing(row_to_print_time=row) == 2:
        break
    if row[12] != "background\n" and row[12] != "scan11\n" and row[12] != "scan44\n":
        continue
    if row[12] == "scan11\n" or row[12] == "scan44\n":
        flag=True
    count=count+1
    if check_suspicious(flow=row) != 0:
        count_total=count_total+1
        if row[12]=="scan11\n" or row[12]=="scan44\n":
            count_abnormal=count_abnormal+1

if flag:
    print("Yes,it consists of scanning activity.")
print("Total flow count:",count)
print("Total suspicious count:",count_total,"actual abnormal:",count_abnormal,"rate:",count_abnormal/count_total)
