#!/bin/python
# -*- coding=utf-8 -*-
 
#import logging
#import re
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
 
#设置目的端口号
dstport = 80
#随机产生源端口
sportid = random.randint(1024, 2000)
#随机产生seqid
seqid = random.randint(20000, 30000)
 
#产生SYN包（FLAG = 2 为SYN）
result_raw_synack = sr(IP(dst='192.168.100.100')/TCP(dport=dstport,sport=sportid,flags=2,seq=seqid), verbose = False)
 
#响应的数据包产生数组([0]为响应，[1]为未响应)
result_synack_list = result_raw_synack[0].res
 
#第一层[0]位第一组数据包
#第二层[0]表示发送的包，[1]表示收到的包
#第三层[0]为IP信息，[1]为TCP信息，[2]为TCP数据
tcpfields_synack = result_synack_list[0][1][1].fields
 
#由于SYN算一个字节，所以客户到服务器序列号（sc_sn)需要增加1
sc_sn = tcpfields_synack['seq'] + 1
cs_sn = tcpfields_synack['ack']
 
#发送ACK(flag = 16),完成三次握手！
send(IP(dst='192.168.100.100')/TCP(dport=dstport,sport=sportid,flags=16,seq=cs_sn,ack=sc_sn), verbose = False)
 
#发送数据（b"Welcome to qytang"），flag为24（ACK = 16，PUSH = 8)
#注意'multi=1'，服务器会先给一个ACK确认，然后发送回显数据。
#如果客户没有及时确认，还会有多次重传！
result_raw_msg = sr(IP(dst='192.168.100.100')/TCP(dport=dstport,sport=sportid,flags=24,seq=cs_sn,ack=sc_sn)/b"Welcome to qytang", verbose = False, multi=1, timeout=1)
 
#响应的数据包产生数组([0]为响应，[1]为未响应)
result_msg_list = result_raw_msg[0].res
 
#提取服务器响应包的IP信息，生成字典（注意是提取的第二组数据，第一组仅仅是ACK）
msgback_ip_fields = result_msg_list[1][1][0].fields
#提取服务器响应包的TCP信息，生成字典（注意是提取的第二组数据，第一组仅仅是ACK）
msgback_tcp_fields = result_msg_list[1][1][1].fields
#提取服务器响应包的TCP数据信息，生成字典（注意是提取的第二组数据，第一组仅仅是ACK）
msgback_data_fields = result_msg_list[1][1][2].fields
 
#如果回显数据中有'Echo'字段就打印回显内容
if re.search(b'Echo', msgback_data_fields['load']):
    print(msgback_data_fields['load'])
 
#技术数据长度，ip总长度 - ip头部长度（['ihl']*4） - tcp头部长度（['dataofs']*4）
data_len = msgback_ip_fields['len'] - msgback_ip_fields['ihl']*4 - msgback_tcp_fields['dataofs']*4
 
#客户到服务器端的序列号为，服务器回显中的'seq'加上传输的数据长度！
sc_sn = msgback_tcp_fields['seq'] + data_len
cs_sn = msgback_tcp_fields['ack']
 
#发送ACK对服务器的回显进行确认，flag = 16（ACK）
send(IP(dst='192.168.100.100')/TCP(dport=dstport,sport=sportid,flags=16,seq=cs_sn,ack=sc_sn), verbose = False)
 
#客户端主动发送FIN（1） + ACK（16），进行连接终结。
result_raw_fin = sr1(IP(dst='192.168.100.100')/TCP(dport=dstport,sport=sportid,flags=17,seq=cs_sn,ack=sc_sn), verbose = False)
 
#由于FIN算一个字节，所以客户到服务器序列号（sc_sn)需要增加1
#sc_sn = result_raw_fin[1].fields['seq'] + 1
sc_sn = result_raw_fin[1].fields['seq']
cs_sn = result_raw_fin[1].fields['ack']
 
#发送最后一个ACK（16），结束整个TCP连接！！！
send(IP(dst='192.168.100.100')/TCP(dport=dstport,sport=sportid,flags=16,seq=cs_sn,ack=sc_sn), verbose = False)
