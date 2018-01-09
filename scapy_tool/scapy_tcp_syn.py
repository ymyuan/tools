#!/bin/python
# -*- coding=utf-8 -*-
import sys
from scapy.all import *

# 设置目的端口号
dstport = 56789
# 随机产生源端口
#sportid = random.randint(1024, 2000)
print("%s %d" %(sys.argv[0],int(sys.argv[1])))
if len(sys.argv) == 2 :
    sportid = int(sys.argv[1])
else :
    sportid = random.randint(1024, 2000)
# 随机产生seqid
seqid = random.randint(20000, 30000)

# 产生SYN包（FLAG = 2 为SYN）
result_raw_synack = sr(IP(dst='192.168.200.200') / TCP(dport=dstport, sport=sportid, flags=2, seq=seqid), verbose=False)

# 响应的数据包产生数组([0]为响应，[1]为未响应)
result_synack_list = result_raw_synack[0].res

# 第一层[0]位第一组数据包
# 第二层[0]表示发送的包，[1]表示收到的包
# 第三层[0]为IP信息，[1]为TCP信息，[2]为TCP数据
tcpfields_synack = result_synack_list[0][1][1].fields

# 由于SYN算一个字节，所以客户到服务器序列号（sc_sn)需要增加1
sc_sn = tcpfields_synack['seq'] + 1
cs_sn = tcpfields_synack['ack']

# 发送ACK(flag = 16),完成三次握手！
send(IP(dst='192.168.200.200') / TCP(dport=dstport, sport=sportid, flags=16, seq=cs_sn, ack=sc_sn), verbose=False)

#print("seq=%d, ack=%d" %(cs_sn, sc_sn))
#print("end")
