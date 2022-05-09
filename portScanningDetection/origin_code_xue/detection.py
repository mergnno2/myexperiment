# 滑动窗口，增删。2min*5。 瞬时流数量超过平均值的2.65倍，做异常检测。否则，每两分钟检测一次。
# 检测根据sip，dip字典中大流量进行。
# 平均值随滑动窗口动态更新
import detection_core

import pymysql.cursors

connect = pymysql.connect(host='localhost', port=3306, user='root', password='root', db='cidds', charset='utf8')

import time

cursor1 = connect.cursor()

# 从12:00开始到14:15结束. 日期3.17
#               0    1      2       3       4      5    6      7      8     9    10  WHERE  and m_level BETWEEN 0 AND 1440
s1 = "SELECT  Date,Src_IP,Dst_IP,m_level,Src_Pt,Dst_Pt,Proto,Flags,Packets,Bytes FROM week1_21"
cursor1.execute(s1)
row = cursor1.fetchall()
length = len(row)
print(length)
cursor1.close()
# 读取前5个窗口的数据，创建字典sip，dip.
begin = 0  # 起始时间
term_num = 0  # 每秒钟数量
long_num = [0]  # 10分钟内间隔2min的行号，10个值

detection = 0  # 检测函数

# ping只要sip字典
ping_sip = {}
ping_list = []

web_sip = {}
web_dip = {}
web_list = []

share_sip = {}
share_dip = {}
share_list = []

brute_sip = {}
brute_dip = {}
brute_list = []

# flags中的SYN对应的sip
SYN_sip = {}

ACKSYN_sip = {}

last_list = []


en_v1=[]
en_v2=[]
en_v3=[]
en_v4=[]
en_v5=[]
en_v6=[]


# 起始4个窗口
pre_num = 0
for pre_num in range(length):
    date = row[pre_num][0]
    day, second = str(date).split(" ")
    h, m, s = second.split(":")
    # a,b=s.split(".") 2017-03-21 00:00:21
    year, mon, day1 = day.split("-")
    time_s = (((int(day1) - 21) * 24 +
               int(h)) * 60 +
              int(m)) * 60 + \
             int(float(s))

    # 每秒的流数量。
    if time_s > begin:
        begin = begin + 1
        term_num = 0

        if begin % 120 == 0:
            long_num.append(pre_num)
        if begin >= 1080:
            break
    term_num = term_num + 1

    if row[pre_num][7][4] == 'S':
        if SYN_sip.__contains__(row[pre_num][1]):
            SYN_sip[row[pre_num][1]] += 1
        else:
            SYN_sip[row[pre_num][1]] = 1

        if row[pre_num][7][1] == 'A':
            if ACKSYN_sip.__contains__(row[pre_num][1]):
                ACKSYN_sip[row[pre_num][1]] += 1
            else:
                ACKSYN_sip[row[pre_num][1]] = 1

    # 构建源、目的80端口对应的sip、dip字典，对大于一定数量的IP求联合熵
    if row[pre_num][6] == 'ICMP ':
        # ping类型
        ping_list.append(pre_num)
        if row[pre_num][1] in ping_sip.keys():
            ping_sip[row[pre_num][1]] += 1
        else:
            ping_sip[row[pre_num][1]] = 1
            # continue

    # 构建139,455端口对应的sip、dip字典，对大于一定数量的IP求联合熵

    # 构建22端口对应的sip、dip字典，对大于一定数量的IP求联合熵
    if row[pre_num][5] == 22 \
            or row[pre_num][4] == 22:
        # bruteforce类型
        brute_list.append(pre_num)
        if row[pre_num][1] in brute_sip.keys():
            brute_sip[row[pre_num][1]] += 1
        else:
            brute_sip[row[pre_num][1]] = 1

        if row[pre_num][2] in brute_dip.keys():
            brute_dip[row[pre_num][2]] += 1
        else:
            brute_dip[row[pre_num][2]] = 1

            # continue

    # 构建其他类型的sip，dip字典，对大于一定数量的IP求联合熵,主要是针对portscan类型
    last_list.append(pre_num)

print(long_num)
print(begin)

avg = pre_num / 1080
N = 2.65 * avg * 1000  # 每秒平均量的系数

attack_ping = []
attack_dos = []
attack_brute = []
attack_portA = []
attack_portB = []

ddd = []
sss = None
time_distrition = []
for num in range(pre_num, length):
    date = row[num][0]
    day, second = str(date).split(" ")
    h, m, s = second.split(":")
    # a, b = s.split(".")
    # time_s = ((int(h)) * 60 + int(m)-0) * 60 + int(s)
    year, mon, day1 = day.split("-")
    time_s = (((int(day1) - 21) * 24 + int(h)) * 60 + int(m)) * 60 + int(float(s))
    # 每秒的流数量。

    while time_s > begin:
        begin = begin + 1

        if (begin % 120) == 0:
            start = 0

            # 检查icmp
            top_ping_sip = sorted(ping_sip.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序

            # detection   # 大于阈值就要做出检测，保证实时性。检测仍然使用字典中的大流量来做。
            for n in range(len(top_ping_sip)):
                if top_ping_sip[n][1] > 20:  # ping类型的攻击阈值设置的低一点
                    outputA, empty = detection_core.sip_detect(top_ping_sip[n][0], row, ping_list)  # ping类型只检查A 100
                    if outputA == '100':
                        detection = 'pingScan'  # 出现ping攻击啦，赶快标记。
                        # sign标记函数,更新attack_ping
                        #detection_core.sign(top_ping_sip[n][0], row, ping_list, attack_ping)
                else:
                    break

            # 检测brute
            top_brute_sip = sorted(brute_sip.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
            #
            for n in range(len(top_brute_sip)):
                if top_brute_sip[n][1] > 10:  # ping类型的攻击阈值设置的低一点
                    outputA, topdip = detection_core.sip_detect(top_brute_sip[n][0], row,
                                                                brute_list)  # brute类型检查AB dos 001 001 回复010 010
                    if outputA == '001':
                        outputB = detection_core.dip_detect(topdip, row, brute_list)
                        if outputB == '001':
                            detection = 'brute'
                            #detection_core.sign(top_brute_sip[n][0], row, brute_list, attack_brute)

                else:
                    break

            # 根据flags的回复情况决定是否做检测
            top_SYN_sip = sorted(SYN_sip.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
            for n in range(len(top_SYN_sip)):
                # if top_SYN_sip[0][1] > 100000:
                #     break
                if top_SYN_sip[n][1] > 8:  #
                    # detection_core.find(top_SYN_sip[n][0], row, last_list, attack_portA, attack_portB)
                    if ACKSYN_sip.get(top_SYN_sip[n][0]):
                        ack_count = ACKSYN_sip.get(top_SYN_sip[n][0])
                        # print(float(ack_count))
                        # print(float(top_SYN_sip[n][1]))

                        if float(ack_count) / float(top_SYN_sip[n][1]) < 0.9:
                            pass
                            #detection_core.find(top_SYN_sip[n][0], row, last_list, attack_portA, attack_portB)
                    else:
                        pass
                        #detection_core.find(top_SYN_sip[n][0], row, last_list, attack_portA, attack_portB)

                    ddd.append(top_SYN_sip[n][0])

                else:
                    break

            #endd = last_list.pop()

            print(date)

            # 删除历史流.更新字典，顺序是先增后减。增加后窗口为5，减少后窗口为4.
            for dlt in range(long_num[0], long_num[1]):
                if row[dlt][6] == 'ICMP ':
                    # ping类型
                    ping_list.remove(dlt)
                    if ping_sip[row[dlt][1]] > 1:
                        ping_sip[row[dlt][1]] -= 1
                    else:
                        ping_sip.pop(row[dlt][1])

                # 构建22端口对应的sip、dip字典，对大于一定数量的IP求联合熵
                if row[dlt][5] == 22 \
                        or row[dlt][4] == 22:
                    # bruteforce类型
                    brute_list.remove(dlt)
                    if brute_sip[row[dlt][1]] > 1:
                        brute_sip[row[dlt][1]] -= 1
                    else:
                        brute_sip.pop(row[dlt][1])

                    if brute_dip[row[dlt][2]] > 1:
                        brute_dip[row[dlt][2]] -= 1
                    else:
                        brute_dip.pop(row[dlt][2])

                # 构建其他类型的sip，dip字典，对大于一定数量的IP求联合熵,主要是针对portscan类型
                if dlt in last_list:
                    last_list.remove(dlt)

                if row[dlt][7][4] == 'S':
                    if SYN_sip[row[dlt][1]] > 1:
                        SYN_sip[row[dlt][1]] -= 1
                    else:
                        SYN_sip.pop(row[dlt][1])
                    if row[dlt][7][1] == 'A':
                        if ACKSYN_sip[row[dlt][1]] > 1:
                            ACKSYN_sip[row[dlt][1]] -= 1
                        else:
                            ACKSYN_sip.pop(row[dlt][1])

            elapsed = 0
            time_distrition.append(elapsed)
            # 更新数组指针位置
            long_num[0] = num
            long_num.sort()  # 排序后保证每次能够替换掉最小的序号

        # else:
        #
        #
        #     if term_num > N:  # N=2.65*avg  avg动态更新
        #
        #         # 检查icmp
        #         top_ping_sip = sorted(ping_sip.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
        #
        #         # detection   # 大于阈值就要做出检测，保证实时性。检测仍然使用字典中的大流量来做。
        #         for n in range(len(top_ping_sip)):
        #             if top_ping_sip[n][1] > 20:  # ping类型的攻击阈值设置的低一点
        #                 outputA, empty = detection_core.sip_detect(top_ping_sip[n][0], row, ping_list)  # ping类型只检查A 100
        #                 if outputA == '100':
        #                     detection = 'pingScan'  # 出现ping攻击啦，赶快标记。
        #                     # sign标记函数,更新attack_ping
        #                     detection_core.sign(top_ping_sip[n][0], row, ping_list, attack_ping)
        #             else:
        #                 break
        #
        #         # 检测web，2分钟窗口。直接求熵.web的sip->dip熵值大些，dos的sip->dip熵值几乎为0
        #         top_web_sip = sorted(web_sip.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
        #
        #         # 如果sip，dip数量少于50不能构成dos攻击
        #         for n in range(len(top_web_sip)):
        #             if top_web_sip[n][1] > 100:  #
        #                 outputA, topdip = detection_core.sip_detect(top_web_sip[n][0], row,
        #                                                             web_list)  # web类型检查AB dos 001 001 回复010 010
        #                 if outputA == '001':
        #                     outputB = detection_core.dip_detect(topdip, row, web_list)
        #                     if outputB == '001':
        #                         detection = 'dos'
        #                         detection_core.sign(top_web_sip[n][0], row, web_list, attack_dos)
        #             else:
        #                 break
        #
        #         # 检测brute
        #         top_brute_sip = sorted(brute_sip.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
        #
        #         #
        #         for n in range(len(top_brute_sip)):
        #             if top_brute_sip[n][1] > 50:  # ping类型的攻击阈值设置的低一点
        #                 outputA, topdip = detection_core.sip_detect(top_brute_sip[n][0], row,
        #                                                             brute_list)  # brute类型检查AB dos 001 001 回复010 010
        #                 if outputA == '001':
        #                     outputB = detection_core.dip_detect(topdip, row, brute_list)
        #                     if outputB == '001':
        #                         detection = 'brute'
        #                         detection_core.sign(top_brute_sip[n][0], row, brute_list, attack_brute)
        #
        #             else:
        #                 break
        #
        #         # 检测last 找portscan类型攻击。需要三维的检测方法。
        #         top_last_sip = sorted(sip.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
        #         top_last_dip = sorted(dip.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
        #         top_last_dpt = sorted(dpt.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
        #
        #         # 如果sip，dip数量少于50不能构成dos攻击
        #         for nsip in top_last_sip:
        #             if nsip[1] > 40:
        #                 # 检测联合熵
        #                 sip_dip_dpt = {}
        #                 sip_dpt_dip = {}
        #                 # sip_spt = {}
        #
        #                 for ndip in top_last_dip:
        #                     if ndip[1] > 40:
        #                         v1 = detection_core.sip_dip_dpt_detect(nsip[0], ndip[0], row, last_list)
        #                         if v1 == 'portB':  # 垂直扫描
        #                             detection_core.signportB(nsip[0], ndip[0], row, last_list, attack_portB)
        #
        #                 for ndpt in top_last_dpt:
        #                     if ndpt[1] > 40:
        #                         v2 = detection_core.sip_dpt_dip_detect(nsip[0], ndpt[0], row, last_list)
        #                         detection_core.signportA(nsip[0], ndpt[0], row, last_list, attack_portA)

        term_num = 0  # 每秒钟的流数量，检测后重置

    # 计数-每秒的流数量
    term_num = term_num + 1

    # 添加新的流,更新sip，dip字典，
    if row[num][6] == 'ICMP ':
        # ping类型,只找sip，不用dip
        ping_list.append(num)
        if ping_sip.__contains__(row[num][1]):
            ping_sip[row[num][1]] += 1
        else:
            ping_sip[row[num][1]] = 1

    # 构建22端口对应的sip、dip字典，对大于一定数量的IP求联合熵
    if row[num][5] == 22 \
            or row[num][4] == 22:
        # bruteforce类型
        brute_list.append(num)
        if brute_sip.__contains__(row[num][1]):
            brute_sip[row[num][1]] += 1
        else:
            brute_sip[row[num][1]] = 1

        if brute_dip.__contains__(row[num][2]):
            brute_dip[row[num][2]] += 1
        else:
            brute_dip[row[num][2]] = 1

    # 构建其他类型的sip，dip字典，对大于一定数量的IP求联合熵,主要是针对portscan类型
    last_list.append(num)
    if row[num][7][4] == 'S':
        if SYN_sip.__contains__(row[num][1]):
            SYN_sip[row[num][1]] += 1
        else:
            SYN_sip[row[num][1]] = 1
        if row[num][7][1] == 'A':
            if ACKSYN_sip.__contains__(row[num][1]):
                ACKSYN_sip[row[num][1]] += 1
            else:
                ACKSYN_sip[row[num][1]] = 1

elapsed = 0
print("Time used:", elapsed)

print('--------------------------')
print('--------------------------')
print('--------------------------')

