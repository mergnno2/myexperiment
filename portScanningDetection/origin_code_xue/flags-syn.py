import pymysql.cursors
connect=pymysql.connect(host='localhost',port=3306,user='root',password='root',db='cidds',charset='utf8')
cursor1 = connect.cursor()
#               0    1      2       3       4      5    6      7      8     9    10  WHERE m_level BETWEEN 0 AND 1440
s1 = "SELECT  flags FROM week1_21 where flags like '____S_' and   type='attacker' and attacktype='portScan' "
cursor1.execute(s1)
row = cursor1.fetchall()
length = len(row)
print(length)
cursor1.close()

spt={}
dpt={}
proto={}
count=0
for data in row:
    if data[0][1]=='A':
        count+=1

print(count)
print(count/length)

# import pymysql.cursors
# connect=pymysql.connect(host='localhost',port=3306,user='root',password='root',db='cidds',charset='utf8')
# cursor1 = connect.cursor()
# #               0    1      2       3       4      5    6      7      8     9    10  WHERE m_level BETWEEN 0 AND 1440
# s1 = "SELECT  proto FROM week1_21 where   type='attacker' and attacktype='portScan'"
# cursor1.execute(s1)
# row = cursor1.fetchall()
# length = len(row)
# print(length)
# cursor1.close()
#
# tcp=0
# udp=0
# icmp=0
# count=0
# for data in row:
#     if data[0]=='TCP  ':
#         tcp+=1
#     if data[0]=='UDP  ':
#         udp+=1
#     if data[0]=='ICMP ':
#         icmp+=1
#
# # print(count)
# print(tcp/length)
# print(udp/length)
# print(icmp/length)


# from matplotlib import pyplot as plt
# import numpy as np
# import  math
# import copy
#
#
# rate = [0.8405,0.1518,0.0077]
#
# # explode = [0,  0.05, 0, 0.05, 0, 0.05]
# # colors = ['c', 'm','y']
# labels = ['TCP','UDP','others']
#
# # plt.pie(rate, explode=explode, colors=colors, labels=labels)
# explode = [0, 0,0.05]
# plt.pie(rate,   labels=labels,explode=explode,autopct='%2.3f%%',startangle=90)
# # plt.legend(loc='upper left', bbox_to_anchor=(-0.1, 1))
#
# plt.show()