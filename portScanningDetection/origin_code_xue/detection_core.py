import  math
#                 0    1      2       3       4      5    6      7      8     9    10
# s1 = "SELECT  Date,Src_IP,Dst_IP,m_level,Src_Pt,Dst_Pt,Proto,Flags,Packets,Bytes,num

def sip_detect(sip,row,list_d):
    sip_dip = {}
    sip_dpt={}
    sip_spt={}
    length=0
    for ln in list_d:
        if row[ln][1]==sip:
            length+=1

            # sip_dip
            if  sip_dip.__contains__(row[ln][2]):
                sip_dip[row[ln][2]] += 1
            else:
                sip_dip[row[ln][2]] = 1

            # sip_dpt
            if   sip_dpt.__contains__(row[ln][5]):
                sip_dpt[row[ln][5]] += 1
            else:
                sip_dpt[row[ln][5]] = 1

            # sip_spt
            if   sip_spt.__contains__(row[ln][4]):
                sip_spt[row[ln][4]] += 1
            else:
                sip_spt[row[ln][4]] = 1

    v1 = 0
    for values in sip_dip.values():
        pi = int(values) / length
        lpi = -math.log2(pi)
        v1 += (pi * lpi)
    v1=v1/math.log2(length)

    # print(v1)

    v2 = 0
    for values in sip_dpt.values():
        pi = int(values) / length
        lpi = -math.log2(pi)
        v2 += (pi * lpi)
    v2= v2 / math.log2(length)
    # print(v1)

    v3 = 0
    for values in sip_spt.values():
        pi = int(values) / length
        lpi = -math.log2(pi)
        v3 += (pi * lpi)
        # print(v1)
    v3 = v3 / math.log2(length)

    top_sip_dip = sorted(sip_dip.items(), key=lambda x: x[1], reverse=True)  # 按值数递减排序
    outcome='benign'
    if v1>0.7:
        if v2<0.3:
            if v3<0.3:
                outcome='100'               #proto是ICMP
    else:
        if v1<0.3:
            if v2<0.3:
                if v3>0.7:
                    outcome='001'   # dos或brute
                else:
                    if v3>0.3:
                        outcome = '0x1'  #brute

    # sip_un=[v1,v2,v3]
    return outcome,top_sip_dip[0][0]



def dip_detect(dip, row, list_d):
    dip_sip = {}
    dip_dpt = {}
    dip_spt = {}
    length = 0
    for ln in list_d:
        if row[ln][2] == dip:
            length += 1

            # dip_sip
            if   dip_sip.__contains__(row[ln][1]):
                dip_sip[row[ln][1]] += 1
            else:
                dip_sip[row[ln][1]] = 1

            # dip_dpt
            if   dip_dpt.__contains__(row[ln][5]):
                dip_dpt[row[ln][5]] += 1
            else:
                dip_dpt[row[ln][5]] = 1

            # dip_spt
            if   dip_spt.__contains__(row[ln][4]):
                dip_spt[row[ln][4]] += 1
            else:
                dip_spt[row[ln][4]] = 1

    v1 = 0
    for values in dip_sip.values():
        pi = int(values) / length
        lpi = -math.log2(pi)
        v1 += (pi * lpi)
    v1 = v1 / math.log2(length)

    # print(v1)

    v2 = 0
    for values in dip_dpt.values():
        pi = int(values) / length
        lpi = -math.log2(pi)
        v2 += (pi * lpi)
    v2 = v2 / math.log2(length)
    # print(v1)

    v3 = 0
    for values in dip_spt.values():
        pi = int(values) / length
        lpi = -math.log2(pi)
        v3 += (pi * lpi)
        # print(v1)
    v3 = v3 / math.log2(length)

    outcome='benign'
    if v1 < 0.3:
        if v2 < 0.3:
            if v3 > 0.7:
                outcome = '001'  # dos或brute
            else:
                if v3 > 0.3:
                    outcome = '0x1'  # brute


    return outcome

# 标记攻击位置
def sign(sip,row,list_d,attack_model):
    for ln in list_d:
        if row[ln][1]==sip:
            num = row[ln][10]
            if num not in attack_model:
                attack_model.append(num)
    return attack_model

#                 0    1      2       3       4      5    6      7      8     9    10
# s1 = "SELECT  Date,Src_IP,Dst_IP,m_level,Src_Pt,Dst_Pt,Proto,Flags,Packets,Bytes,num

def sip_dip_detect(sip,dip,row,list_d):
    sip_dip = {}
    Packets=0
    term_len=0
    remove_dpt = []  # 访问次数大于5的IP要去除。
    for ln in list_d:
        if row[ln][1] == sip:
            if row[ln][2] == dip:
                if row[ln][9]<100:      #Bytes<100
                    term_len += 1

                    # Packets += int(row[ln][8])

                    # sip_dip -> dpt
                    if sip_dip.__contains__(row[ln][5]):
                        sip_dip[row[ln][5]] += 1
                    else:
                        sip_dip[row[ln][5]] = 1

                    if row[ln][9] > 200:  # Bytes<100
                        remove_dpt.append(row[ln][2])
                        # term_len += 1
    for dpt in sip_dip.keys():
        if sip_dip[dpt]>10:
            remove_dpt.append(dpt)
    for dpt in set(remove_dpt):  #去除时先将要去的dip存在列表中，不能直接在循环中去除
        sip_dip.pop(dpt)

    v1 = 0

    if term_len < 6:
        sip_dip.clear()
        return 'begin'


    # if (Packets/term_len)>1.5:
    #     return 'begin'


    for values in sip_dip.values():
        pi = int(values) / term_len
        lpi = -math.log2(pi)
        v1 += (pi * lpi)
    if len(sip_dip) > 1:
        v1 = v1 / math.log2(term_len)

    if v1>0.7:
        return 'portB'


def sip_dpt_detect(sip, dpt, row, list_d,attack_portA):
    sip_dpt = {}
    sip_dpt_len={}
    Packets = 0
    term_len = 0
    tt_len=0
    remove_dip = []  # 访问次数大于10的IP要去除。
    for ln in list_d:
        if row[ln][1] == sip:
            if row[ln][5] == dpt:

                Packets += int(row[ln][8])
                # sip_dpt -> dip
                if sip_dpt.__contains__(row[ln][2]):
                    sip_dpt[row[ln][2]] += 1
                else:
                    sip_dpt[row[ln][2]] = 1

                if sip_dpt_len.__contains__(row[ln][9]):
                    sip_dpt_len[row[ln][9]] += 1
                else:
                    sip_dpt_len[row[ln][9]] = 1

                if row[ln][9] > 200:  # Bytes<100
                    remove_dip.append(row[ln][2])
                tt_len += 1

    for dip in sip_dpt.keys():
        if sip_dpt[dip]>5:
            remove_dip.append(dip)
    for dip in set(remove_dip):  #去除时先将要去的dip存在列表中，不能直接在循环中去除
        sip_dpt.pop(dip)

    for values in sip_dpt.values():
        term_len+=values
    v2 = 0
    if term_len < 6:
        sip_dpt.clear()
        return 'begin'

    # if (Packets/term_len)>7:
    #     return 'begin'

    for values in sip_dpt.values():
        pi = int(values) / term_len
        lpi = -math.log2(pi)
        v2 += (pi * lpi)
    if len(sip_dpt) > 1:
        v2 = v2 / math.log2(term_len)



    # if int(dpt)==80 or int(dpt)==443:
    #
    #     if v2>0.5:
    #         print(v2)
    #         return 'portA'
    #     else:
    #         if sip == '192.168.220.16':
    #             print(v2)
    # else:
    if v2>0.7:
        for ln in list_d:
            if row[ln][1] == sip:
                if row[ln][5] == dpt:
                    dip=row[ln][2]
                    if dip not in remove_dip:
                        num = row[ln][10]
                        if num not in attack_portA:

                            v3=0
                            for values in sip_dpt_len.values():
                                pi = int(values) / tt_len
                                lpi = -math.log2(pi)
                                v3 += (pi * lpi)
                            if len(sip_dpt_len) > 1:
                                v3 = v3 / math.log2(tt_len)
                            if v3<0.7:
                                attack_portA.append(num)
                    # else:print(v2)
        return attack_portA

# 标记垂直端口扫描的攻击位置
def signportB(sip,dip,row,list_d,attack_model):
    for ln in list_d:
        if row[ln][1]==sip:
            if row[ln][2] == dip:
                num = row[ln][10]
                if num not in attack_model:
                    attack_model.append(num)
    return attack_model

# 标记水平端口扫描的攻击位置
def signportA(sip,dpt,row,list_d,attack_model):
    for ln in list_d:
        if row[ln][1]==sip:
            if row[ln][5] == dpt:
                num = row[ln][10]
                if num not in attack_model:
                    attack_model.append(num)
    return attack_model


def find(sip,row,list,attack_portA,attack_portB):
    dip={}
    dpt={}
    detect_list=[]
    for n in list:
        if row[n][1]==sip:
            detect_list.append(n)
    for m in detect_list:
        if dip.__contains__(row[m][2]):
            dip[row[m][2]]+=1
        else:
            dip[row[m][2]]=1

        if dpt.__contains__(row[m][5]):
            dpt[row[m][5]]+=1
        else:
            dpt[row[m][5]]=1
    top_last_dip = sorted(dip.items(), key=lambda x: x[1], reverse=True)
    top_last_dpt = sorted(dpt.items(), key=lambda x: x[1], reverse=True)
    for ndip in top_last_dip:
        if ndip[1] >= 6:
            v1 = sip_dip_detect(sip, ndip[0], row, detect_list)
            if v1 == 'portB':  # 垂直扫描
                signportB(sip, ndip[0], row, detect_list, attack_portB)
        else:
            break
    for ndpt in top_last_dpt:
        if ndpt[1] >= 6:
            # v2 =
            sip_dpt_detect(sip, ndpt[0], row, detect_list,attack_portA)
            # if v2 == 'portA':  # 垂直扫描
            #     signportA(sip, ndpt[0], row, detect_list, attack_portA)
        else:
            break

    return (attack_portA,attack_portB)