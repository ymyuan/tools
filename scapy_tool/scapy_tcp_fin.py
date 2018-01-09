#!/bin/python
# -*- coding=utf-8 -*-

import sys
from scapy.all import *
dstport = 80
sportid = 55555

if len(sys.argv) == 3:
    cs_sn = sys.argv[1]
    sc_sn = sys.argv[2]

    #客户端主动发送FIN（1） + ACK（16），进行连接终结。
    result_raw_fin = sr1(IP(dst='192.168.100.100')/TCP(dport=dstport,sport=sportid,flags=17,seq=cs_sn,ack=sc_sn), verbose = False)

    #由于FIN算一个字节，所以客户到服务器序列号（sc_sn)需要增加1
    sc_sn = result_raw_fin[1].fields['seq'] + 1
    cs_sn = result_raw_fin[1].fields['ack']

    #发送最后一个ACK（16），结束整个TCP连接！！！
    send(IP(dst='192.168.100.100')/TCP(dport=dstport,sport=sportid,flags=16,seq=cs_sn,ack=sc_sn), verbose = False)
