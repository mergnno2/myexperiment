# import pymysql.cursors
# connect=pymysql.connect(host='localhost',port=3306,user='root',password='root',db='cidds',charset='utf8')
# cursor1 = connect.cursor()
# #               0    1      2       3       4      5    6      7      8     9    10  WHERE m_level BETWEEN 0 AND 1440
# s1 = "SELECT  Src_Pt,Dst_Pt,Proto FROM week3  "
# cursor1.execute(s1)
# row = cursor1.fetchall()
# length = len(row)
# print(length)
# cursor1.close()
#
# spt={}
# dpt={}
# proto={}
#
# for data in row:
#     if data[0] in spt.keys():
#         spt[data[0]] += 1
#     else:
#         spt[data[0]] = 1
#
#     if data[1] in dpt.keys():
#         dpt[data[1]] += 1
#     else:
#         dpt[data[1]] = 1
#
#     if data[2] in proto.keys():
#         proto[data[2]] += 1
#     else:
#         proto[data[2]] = 1
# top_spt = sorted(spt.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
# top_dpt = sorted(dpt.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
# top_proto = sorted(proto.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
#
# # sptx=[]
# # spty=[]
# # for nspt in top_spt:
# #     if nspt[1] > 100:
# #         sptx.append(nspt[0])
# #         spty.append(nspt[1])
# #
# # dptx=[]
# # dpty=[]
# # for ndpt in top_dpt:
# #     if ndpt[1] > 100:
# #         dptx.append(ndpt[0])
# #         dpty.append(ndpt[1])
# #
# # protox=[]
# # protoy=[]
# # for nproto in top_proto:
# #     if nproto[1] > 100:
# #         protox.append(nproto[0])
# #         protoy.append(nproto[1])
# #
# # f = open("F:/statistics3.txt", "w+")
# # f.write(str(protox))
# # f.write(str(protoy))
# # f.close()
# #
# # f = open("F:/statistics2.txt", "w+")
# # f.write(str(dptx))
# # f.write(str(dpty))
# # f.close()
# #
# # f = open("F:/statistics1.txt", "w+")
# # f.write(str(sptx))
# # f.write(str(spty))
# # f.close()
# print(spt)
# for i in range(20):
#     print(top_spt[i])
#
# print(dpt)
# for i in range(20):
#     print(top_dpt[i])


# 6349783
# # dpt
# (443, 1409649)
# (80, 1069486)
# (53, 444219)
# (5353, 6156)
# (445, 167877)
# (8082, 44469)
# (137, 37075)
# (138, 22260)
from matplotlib import pyplot as plt
import numpy as np
import  math
import copy
all=6349783
other=all-1409649-1069486-444219- 6156-167877-44469-37075-22260

rate = [1069486/all,167877/all,(1409649+44469)/all,(37075+22260)/all,(444219+6156)/all,other/all]
size = [1069486/all,167877/all,(1409649+44469)/all,(37075+22260)/all,(444219+6156)/all,other/all]

# explode = [0,  0.05, 0, 0.05, 0, 0.05]
# colors = ['c', 'm','y']
labels = ['HTTPS:443','NetBIOS:137,138','HTTP:80','share:445','DNS:53', 'others']

# plt.pie(rate, explode=explode, colors=colors, labels=labels)
plt.pie(rate,   labels=labels,autopct='%2.2f%%',startangle=90)
plt.legend(loc='upper left', bbox_to_anchor=(-0.1, 1))

plt.show()