import  math
from matplotlib import pyplot as plt
from matplotlib.ticker import MultipleLocator, FormatStrFormatter

import numpy as np

import pymysql.cursors
connect=pymysql.connect(host='localhost',port=3306,user='root',password='root',db='cidds',charset='utf8')
cursor=connect.cursor()

import time
start = time.clock()
cursor1 = connect.cursor()


# 正常流量信息
s1 = "SELECT   DATE,Bytes,packets FROM week3 WHERE m_level BETWEEN 540 AND 599 "
cursor1.execute(s1)
row = cursor1.fetchall()
length = len(row)
print(length)
cursor1.close()

begin=0

list_t=[]  #时间
list_n=[]  #包大小
list_k=[]  #流数量
list_p=[]  #包数量
sum=0
k=0
p=0
for num in range(length):
    date = row[num][0]
    day, second = str(date).split(" ")
    h, m, s = second.split(":")
    xlable=int(m)*60+int(s)

    if int(xlable)>begin:
        list_t.append(begin)
        begin=begin+1
        list_n.append(sum)
        sum=0
        list_k.append(k)
        k = 0
        list_p.append(p)
        p = 0

    size=row[num][1]
    # sum=sum+size
    k=k+1
    pack = row[num][2]
    p = p + pack
    print(num)


elapsed = (time.clock() - start)
print("Time used:", elapsed)
cursor.close()
connect.commit()
connect.close()


# 攻击流量信息采集
#预留

fig = plt.figure()
axes = fig.add_axes([0.1, 0.1, 0.9, 0.9])
# axes.plot(list_t, list_k, marker='v',ms=0.1)
# axes.plot(list_t, list_p, marker='x',ms=3)
# axes.plot(list_t, list_n, marker='o',ms=3)


avg=0
for i in list_k:
    avg=avg+i
avg=avg/3600
print(avg)

list_a=[]       #横坐标，平均流量的倍数
list_b=[]       #正常流量的分布情况，纵坐标，低于横坐标值的比例
for h in range(1000):
    print(h)
    big=0
    for j in list_k:
        if j<=(avg*h/200):
            big=big+1
    list_a.append(h/200)
    list_b.append(big/3600)
# 正常流数量图
axes.plot(list_a, list_b, '--',marker='.',ms=0.5)

#（1.68,0.8）的坐标线
plt.grid()  # 生成网格
plt.plot([2.57,2.57],[0,0.9],'--')
plt.plot([0,2.57],[0.9,0.9],'--')
plt.xlabel('k*Avg')
plt.ylabel('Percentage')

plt.text(2.58, 0.86, 'X=2.57', ha='left',va= 'bottom', fontsize=9)
plt.text(2.58, 0.80, 'Y=0.90', ha='left',va= 'bottom', fontsize=9)

plt.show()
print(avg)