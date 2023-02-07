import time
import csv
import re


def calculate_delay(file_path):

    result = 0

    file_scan = open(file_path + "\\scan.txt", "r", newline="")
    file_detect = open(file_path + "\\detection_log.csv", "r", newline="")
    scan_start_time = []
    scan_end_time = []
    detect_time = []
    counter = 0
    for row in file_scan:
        flag = False
        for character in row:
            if character.isalpha():
                flag = True
        if flag:
            continue
        elif len(row) == 20:
            counter = counter + 1
            scan_time_str = row[:-1]
            scan_time_stamp = time.mktime(time.strptime(scan_time_str, '%Y-%m-%d %H:%M:%S'))
            if counter % 2 != 0:
                scan_start_time.append(scan_time_stamp)
            else:
                scan_end_time.append(scan_time_stamp)
    for row in file_detect:
        items = row.split(",")
        if re.search("10.0.0.1", items[1]) is None:
            continue
        detect_time_stamp = time.mktime(time.strptime(str(items[0]), '%Y-%m-%d %H:%M:%S'))
        detect_time.append(detect_time_stamp)

    detected_activity_count = 0
    k = 0
    while k < len(scan_start_time):
        j = 0
        while j < len(detect_time):
            if detect_time[j] > scan_start_time[k]:
                if detect_time[j] < scan_end_time[k]:
                    result = result + detect_time[j] - scan_start_time[k]
                    detected_activity_count = detected_activity_count + 1
                else:
                    print("Scan activity ", k, " not detected!")
                break
            j = j + 1
        k = k + 1

    print(file_path[-15:], "detected activity count:", detected_activity_count,
          "AVG delay:", result/detected_activity_count)
    return


file_paths = []
for i in range(1, 3):
    file_paths.append("C:\\Users\\Supernova\\Desktop\\防止意外发生的部分实验结果存储\\第" + str(i) + "组实验")

for group in file_paths:
    calculate_delay(group + "\\mine")
print("-----------------------------------")

for group in file_paths:
    calculate_delay(group + "\\fixed")
print("-----------------------------------")

for group in file_paths:
    calculate_delay(group + "\\proactive")
