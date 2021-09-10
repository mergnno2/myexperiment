
backup=np.arry(ds_O3_IC)
# 先假设csv里的数据是  7*24的
# 对于给定的某天 day,0<=day<=6
data=backup
result=data
def handle(backup,data,result):# 处理一周数据中最后一天的数据
    # 首先遍历加权数据中的每个值：
    for h in range(0,23):
        for i in row:
            for j in col:
                data[h-24,i,j]  # 这个就是加权数据的每个值 也就是 x
                # 首先计算 x 对应的小时是多少
                h
                # 然后要计算  这七天  第hour小时的所有数据累加： b(x) = 第一天'hour'小时数据  +  第二天 'hour'小时数据  +  .... + 第七天 'hour'小时数据
                bx=0
                for b_day in range(0,6):
                    bx = bx + backup[b_day*24 + hour]  # hour 不变，变的是 b_day  即天数
                # 最后计算 x/b(x) ，更新加权数据
                result[h-24,i,j]=data[h-24,i,j]/bx
    return

for day in range(0,30):
    # 首先计算某一天的全部24小时的加权的值
    for h in range(0,23):
        for i in row:
            for j in col:
                data[h+day*24,i,j]=a[day%7,h]*data[h+day*24,i,j]

    # 如果现在的天数是前7天，则直接跳过
    if day <6:  # 15天   第 15*24  行  8-15天
        result[day]=0
        continue
    # 否则，已经过去至少7天了，那么把当前日期至7天前  这一段的一周数据（包括加权和原始数据）传给函数处理
    handle(backup=backup[(day-6)*24:day*24],data=data[(day-6)*24:day*24],result=result[(day-6)*24:day*24]) # 前者是这七天的原始数据，后者是这7天的加权数据
    # 函数要做的就是：对于最后一天加权数据的每个元素 x ，除以 这个元素 x 对应的小时的7天累加和  b(x)    即：x/b(x)
    # 假如x是 最后一天 第10小时数据   那么  b(x)=第一天10小时数据+第二天10小时数据+...+第七天10小时数据