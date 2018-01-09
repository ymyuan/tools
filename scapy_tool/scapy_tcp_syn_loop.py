#!/bin/python
# -*- coding=utf-8 -*-

from scapy.all import *

# Change log level to suppress annoying IPv6 error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Set up target IP
dstIp = '192.168.100.100'
ip=IP(dst=dstIp)

# Set up target port
dstport = 80


# Generate random source port
#srcport = random.randint(1024,65535)
# RandNum is a class, port的值一直在变化，注意！！！
srcport = RandNum(1024,65535)

# Generate random seq num
#seqid = random.randint(20000, 30000)
seqid = RandNum(20000, 30000)


def fSYN():
    print "\n[*] Sending SYN packet"
    return ip/TCP(sport=srcport, dport=dstport, flags="S", seq=seqid)
	
def fSendAck(x):
    print "\n[*] Receive SYNACK packet"
    if isinstance(x, TCP):
        print "\n[*] Sending ACK packet"
        ACK = ip / TCP(sport=x.dport, dport=dstport, flags="A", seq=x.ack, ack=x.seq + 1)
	send(ACK)
    return

srloop(fSYN(), prn=lambda x:fSendAck(x[1][1]), prnfail=lambda x:x[0].summary(), inter=0.1, timeout=None, count=500)
#srloop(fSYN(), prn=lambda x:x[1].show(), prnfail=lambda x:x[0].summary(), inter=1, timeout=None, count=2)



# # Create SYN packet
# SYN=ip/TCP(sport=srcport, dport=dstport, flags="S", seq=seqid)

# # Send SYN and receive SYN,ACK
# print "\n[*] Sending SYN packet"
# SYNACK=sr1(SYN)

# # send ack, complete 3WHS
# print "\n[*] Sending ACK packet"
# ACK = ip / TCP(sport=SYNACK.dport, dport=dstport, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1)
# send(ACK)

# print "\n[*] Established"
