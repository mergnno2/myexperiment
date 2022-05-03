import  math
from matplotlib import pyplot as plt
from matplotlib.ticker import MultipleLocator, FormatStrFormatter

import numpy as np

import pymysql.cursors
connect=pymysql.connect(host='localhost',port=3306,user='root',password='root',db='cidds',charset='utf8')
cursor=connect.cursor()

# import time
# start = time.clock()
cursor1 = connect.cursor()
#
#
# # 正常流量信息
s1 = "SELECT   m_level,Src_Pt,Dst_Pt FROM week3  where src_ip='192.168.220.15' and m_level between 600 and 901 "
cursor1.execute(s1)
row = cursor1.fetchall()
length = len(row)
print(length)
cursor1.close()

# brute={}
#
# for list in row:
#     if list[0]  in brute.keys():
#         brute[list[0]]+=1
#     else:
#         brute[list[0]] = 1
#
#
#
# s1 = "SELECT   m_level,num FROM week1  where type='attacker' and attacktype='pingscsan'  "
# cursor1.execute(s1)
# row = cursor1.fetchall()
# length = len(row)
# print(length)
# cursor1.close()
#
# ping={}
#
# for list in row:
#     if list[0]  in ping.keys():
#         ping[list[0]]+=1
#     else:
#         ping[list[0]] = 1
#
#
# s1 = "SELECT   m_level,num FROM week1  where type='attacker' and attacktype='portscan'  "
# cursor1.execute(s1)
# row = cursor1.fetchall()
# length = len(row)
# print(length)
# cursor1.close()
#
# port={}
#
# for list in row:
#     if list[0]  in port.keys():
#         port[list[0]]+=1
#     else:
#         port[list[0]] = 1
#
#
# # s1 = "SELECT   m_level,num FROM week1  where type='attacker' and attacktype='dos'  "
# # cursor1.execute(s1)
# # row = cursor1.fetchall()
# # length = len(row)
# # print(length)
# # cursor1.close()
# #


dos={}

for list in row:
    if list[2]== 80 or list[2]== 443 or list[2] == 8 or list[2]== 8000 or list[2]== 8082 :
        if list[0]  in dos.keys():
            dos[list[0]]+=1
        else:
            dos[list[0]] = 1




fig = plt.figure()
axes = fig.add_axes([0.1, 0.1, 0.9, 0.9])


list_a=[]       #横坐标，平均流量的倍数
list_b=[]       #正常流量的分布情况，纵坐标，低于横坐标值的比例
i=0
for h in dos.values():
    i+=1
    list_a.append(i)
    list_b.append(h)
# 正常流数量图
# box = dict(facecolor='yellow', pad=5, alpha=0.2)
plt.grid()  # 生成网格

axes.plot(list_a, list_b, '--',marker='v',ms=3)

#（1.68,0.8）的坐标线

# plt.xlabel('minute')
plt.ylabel('num')
plt.show()




connect.commit()
connect.close()