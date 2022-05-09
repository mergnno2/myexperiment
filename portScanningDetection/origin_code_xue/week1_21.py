# Date first seen,Duration,Proto,Src IP Addr,Src Pt,Dst IP Addr,Dst Pt,Packets,Bytes,Flows,Flags,Tos,class,attackType,attackID,attackDescription
# Date,Duration,Proto,Src_IP,Src_Pt,Dst_IP,Dst_Pt,Packets,Bytes,Flows,Flags,Tos,type,attackType,attackID,attackDescription
# StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label

import pymysql.cursors
connect=pymysql.connect(host='localhost',port=3306,user='root',password='root',db='cidds',charset='utf8')

cursor0=connect.cursor()
cursor0.execute('TRUNCATE TABLE cidds.`week1_21`')
cursor0.close()
#1,501,856
# 1501856
cursor=connect.cursor()
filename='D:/Python/Python37/myexperiment/portScanningDetection/CIDDS-001/traffic/OpenStack/CIDDS-001-internal-week1.csv'
file2 = open(filename, 'rb')
lines = len(file2.readlines())
file2.close()
file = open(filename, 'rb')
# print(lines)
line = file.readline()
# for i in range(2000000):
#     line = file.readline()
for i in range(lines):
    line = file.readline()
    if line:
        line = line.decode()
        # print(line)
        str_strip = line.strip('\n')
        str_split = str_strip.split(',')

        Date = str_split[0]
        data,time=Date.split(" ")
        # print(data,time)
        y,mon,d=data.split("-")
        if int(d)<21:
            continue
        h, m, s = time.split(":")
        # print(h,m,s)
        # m_level=(int(d)-12)*1024+int(h)*60+int(m)

        m_level = (int(d) - 21) * 1024 + int(h) * 60 + int(m)
        # print(m_level)
        Duration = str_split[1]
        Proto = str_split[2]
        Src_IP = str_split[3]
        Src_Pt = str_split[4]
        Dst_IP = str_split[5]
        Dst_Pt = str_split[6]
        Packets = str_split[7]
        Bytes = str_split[8]
        Flows = str_split[9]
        Flags = str_split[10]
        Tos=str_split[11]
        type = str_split[12]
        attackType = str_split[13]
        attackID = str_split[14]
        attackDescription = str_split[15]

        i=i+1
        print(i)
        cursor.execute(
                " insert into week1_21 (Date,m_level,Duration,Proto,Src_IP,Src_Pt,Dst_IP,Dst_Pt,Packets,Bytes,Flows,Flags,Tos,type,attackType,attackID,attackDescription) "
                "values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                [Date,m_level,Duration,Proto,Src_IP,Src_Pt,Dst_IP,Dst_Pt,Packets,Bytes,Flows,Flags,Tos,type,attackType,attackID,attackDescription])
    else:
            break


file.close()
cursor.close()
connect.commit()
connect.close()

import pymysql.cursors
connect=pymysql.connect(host='localhost',port=3306,user='root',password='root',db='cidds',charset='utf8')
# cursor0=connect.cursor()
# cursor0.execute('UPDATE `week1` SET Bytes=(1024*1024*Bytes) WHERE Packets>20 AND Bytes<300')
# cursor0.close()
connect.commit()
connect.close()
