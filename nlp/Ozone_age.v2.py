import netCDF4 as nc
import pandas as pd
import numpy as np 
import xarray as xr

ds = nc.Dataset("/data3/liuhanqing/projects/postproc/2.combine/output/201806_OSAT_bygroup/camx.CN36km.OSAT_bygroup.sa.grd01.ncf" , "r")
ds_O3_IC = ds['O3_IC'][:,0,10:135,0:152]
backup=np.array(ds_O3_IC)
# 先假设csv里的数据是  7*24的
# 对于给定的某天 day,0<=day<=6
data=backup
result=data
flag = false
def handle(backup,data,result):# 处理一周数据中最后一天的数据
    # 首先遍历加权数据中的每个值：
    if flag == false:
        for day in range (0,6):
            for hour in range(0,23):
                bx = 0
                b_day = 0
                while b_day < 7:
                    bx = bx + backup[b_day * 24 + hour]  # hour 不变，变的是 b_day  即天数
                    b_day = b_day + 1
                # 最后计算 x/b(x) ，更新加权数据  data 是加权值后的值
                i = j = 0
                while i < len(data[hour - 24]):
                    while j < len(data[hour - 24, i]):
                        result[day * 24 + hour, i, j] = data[day * 24 + hour, i, j] / bx[i, j]
                        j = j + 1
                    i = i + 1
    else:
        for hour in range(0,23):
            bx=0
            b_day = 0
            while b_day < 7:
                bx = bx + backup[b_day * 24 + hour]  # hour 不变，变的是 b_day  即天数
                b_day = b_day + 1
            # 最后计算 x/b(x) ，更新加权数据  data 是加权值后的值
            i = j = 0
            while i<len(data[hour-24]):
                while j<len(data[hour-24,i]):
                    result[hour-24,i,j]=data[hour-24,i,j]/bx[i,j]
                    j=j+1
                i=i+1
    flag = true
    return
def get_average(result):
    index = 6 * 24
    while index < len(result):
        summery = 0
        day = 0
        while day < 7:
            summery = summery + result[day * 24 + index]
            day=day+1
        result[index]=summery
        index = index +1
    return

data1 = pd.read_csv('/data3/liuhanqing/python/scripts/6.csv',header=None)
a = np.array(data1)
print(a)

for day in range(0,30):

    # 如果现在的天数是前7天，则直接跳过
    if day <6:  # 15天
        flag = false
        result[day]=0
        continue
    # 首先计算某一天的全部24小时的加权的值
    for hour in range(0,23):
        data[hour+day*24]=a[day%7,hour]*data[hour+day*24]
    # 否则，已经过去至少7天了，那么把当前日期至7天前  这一段的一周数据（包括加权和原始数据）传给函数处理
    handle(backup=backup[(day-6)*24:day*24],data=data[(day-6)*24:day*24],result=result[(day-6)*24:day*24]) # 前者是这七天的原始数据，后者是这7天的加权数据
    get_average(result=result)
    # 函数要做的就是：对于最后一天加权数据的每个元素 x ，除以 这个元素 x 对应的小时的7天累加和  b(x)    即：x/b(x)
    # 假如x是 最后一天 第10小时数据   那么  b(x)=第一天10小时数据+第二天10小时数据+...+第七天10小时数据