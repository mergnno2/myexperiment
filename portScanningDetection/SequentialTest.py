# This code refer to the paper "Detection of slow port scans in flow-based network traffic"
# The data set used by the above paper is also "CIDDS-001"
# Start date: 09.09.2021
def get_time(time_string):
    timeArray = time.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = float(time.mktime(timeArray))
    return timeStamp

filepath = "D:\Python\Python37\myexperiment\portScanningDetection\CIDDS-001\\traffic\OpenStack\CIDDS-001-internal-week1.csv"
# open the original csv data file
file = csv.reader(open(filepath, 'r'))

flow_data = []
start_bound = 0
end_bound = 9

timing = 0

isFirstrow = True
head = next(file)
firstrow = next(file)
start = get_time(firstrow[0])
window_index=0

for row in file:

    if isFirstrow:
        flow_data.append([])
        flow_data[index].append(firstrow)
        isFirstrow = False
        continue

    end = get_time(row[0])

    if timeArray.tm_hour > timing:
        print(str(timeArray.tm_hour) + "o'clock")
        timing = timing + 1
    elif timeArray.tm_hour < start_bound:
        continue
    elif timeArray.tm_hour >= end_bound:
        # Calculate precision here.
        exit(0)

    flow_data[window_index].append(row)


    if end - start >= 60:
        start = end
        flow_data.append([])
        window_index = window_index + 1

