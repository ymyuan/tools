#!/bin/python
# -*- coding=utf-8 -*-

import time
 
# Change log level to suppress annoying IPv6 error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
 
# Import scapy
from scapy.all import *
 
# Print info header
print "[*] ACK-GET example"
 
# Prepare GET statement
#get='GET / HTTP/1.1\n\nHost:\n192.168.100.100\n\nKeep-Alive: 60\n\nConnection:\nkeep-alive\n\n'
get='GET / HTTP/1.1\n\nUser-Agent:\ncurl/7.29.0\n\nHost:\n192.168.200.200\n\nAccept:\n*/*\n\n'
 
# Set up target IP
dstIp="192.168.200.200"
ip=IP(dst=dstIp)

# set up target port 
portdst = 80
 
# Generate random source port number
port=RandNum(1024,65535)

# Generate random seq start num
seqid = random.randint(20000, 30000)
 
# Create SYN packet
SYN=ip/TCP(sport=port, dport=portdst, flags="S", seq=seqid)
 
# Send SYN and receive SYN,ACK
print "\n[*] Sending SYN packet"
SYNACK=sr1(SYN)

# send ack, complete 3WHS
print "\n[*] Sending ACK packet"
ACK = ip / TCP(sport=SYNACK.dport, dport=portdst, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1)
send(ACK)

# Create ACK with GET request
#PUSH=ip/TCP(sport=SYNACK.dport, dport=portdst, flags="PA", seq=SYNACK.ack, ack=SYNACK.seq + 1) / get
PUSH=ip/TCP(sport=SYNACK.dport, dport=portdst, flags=25, seq=SYNACK.ack, ack=SYNACK.seq + 1) / get
 
# SEND our ACK-GET request
print "\n[*] Sending ACK-GET packet"
reply,error=sr(PUSH, multi=True, timeout=0.005)
#reply=sr1(PUSH)
 
# print reply from server
# ack
print "\n[*] Reply from server:"
print reply.show()

# get info of msg from server
# push+ack
#server_push = sniff(count=1, filter="tcp and host "+ dstIp, iface = "ens3f1")

#print server_push
#print server_push.show()

#提取服务器响应包的IP信息，生成字典
#msgback_ip_fields = server_push[0][0][1].fields
# [1][1][0] the first[1] means the second packets, the second[1] means the rx packets(0 means tx packets), the third[0] means ip header
msgback_ip_fields = reply[1][1][0].fields
#提取服务器响应包的TCP信息，生成字典
#msgback_tcp_fields = server_push[0][0][2].fields
msgback_tcp_fields = reply[1][1][1].fields
#提取服务器响应包的TCP数据信息，生成字典
#msgback_data_fields = server_push[0][0][3].fields
msgback_data_fields = reply[1][1][2].fields

#print
#print server_push[0][0][3].load
#print msgback_ip_fields
#print msgback_tcp_fields
print msgback_data_fields['load']

#---------------------------------------------------------
#技术数据长度，ip总长度 - ip头部长度（['ihl']*4） - tcp头部长度（['dataofs']*4）
# ihl 表示字长的个数，比如 ihl=5，表示5个字长，一个字长32位，即4字节，ihl=5 就是5*4=20个字节
data_len = msgback_ip_fields['len'] - msgback_ip_fields['ihl']*4 - msgback_tcp_fields['dataofs']*4

sn = msgback_tcp_fields['ack']
an = msgback_tcp_fields['seq']+data_len

#print sn
#print an

#发送ACK对服务器的回显进行确认，flag = 16（ACK）
ACK = ip / TCP(sport=msgback_tcp_fields['dport'], dport=portdst, flags="A", seq=sn, ack=an)
send(ACK, verbose = False)

#客户端主动发送FIN（1） + ACK（16），进行连接终结。
#回应服务端的fin
fin_server_tcp = reply[2][1][1]
sn = fin_server_tcp.ack
an = fin_server_tcp.seq+1
FINACK = ip / TCP(sport=fin_server_tcp.dport, dport=portdst, flags="FA", seq=sn, ack=an)
result_raw_fin = sr1(FINACK, verbose = False)
 
#由于FIN算一个字节，所以客户到服务器序列号（sc_sn)需要增加1
#sn = result_raw_fin[1].fields['seq'] + 1
#an = result_raw_fin[1].fields['ack']
 
#发送最后一个ACK（16），结束整个TCP连接！！！
#ACK = ip / TCP(sport=port, dport=portdst, flags="A", seq=sn, ack=an)
#send(ACK, verbose = False)

#---------------------------------------------------------
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++

 
print '\n[*] Done!'
