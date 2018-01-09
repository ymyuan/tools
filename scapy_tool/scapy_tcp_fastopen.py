#!/bin/python
# -*- coding=utf-8 -*-

from scapy.all import sr1, IP, TCP

dst = "192.168.100.100"
dport = 80

res = sr1(IP(dst=dst)/TCP(dport=dport,flags="S",options=[('TFO', '')]), verbose=False)
print 'TFO' in dict(res[1].options)
