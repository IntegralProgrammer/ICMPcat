#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import threading
import time

from scapy.all import *

IP_DST = sys.argv[1]
PING_INTERVAL = float(sys.argv[2])

PACKET_EMPTY = threading.Event()
PACKET_EMPTY.set()
PACKET = ""

def stdin_reader():
	global PACKET
	while True:
		#Read in a packet from STDIN
		line = sys.stdin.readline()
		if line == '':
			return
		PACKET = line
		
		#CLEAR the event, notifying that a packet is ready
		PACKET_EMPTY.clear()
		
		#WAIT here before reading the next packet
		PACKET_EMPTY.wait(None)

def icmp_reader():
	def process_packet(pkt):
		if pkt.haslayer(IP):
			if pkt[IP].src == IP_DST:
				if pkt.haslayer(ICMP):
					if pkt[ICMP].type == 0:
						payload = str(pkt[ICMP].payload)
						if len(payload) > 1:
							if payload[0] == 'a':
								sys.stdout.write(payload[1:])
								sys.stdout.flush()
	
	sniff(store=0, prn=process_packet)

#Spawn a thread of stdin_reader()
t_stdin_reader = threading.Thread(target=stdin_reader)
t_stdin_reader.setDaemon(True)
t_stdin_reader.start()

#Spawn a thread of icmp_reader()
t_icmp_reader = threading.Thread(target=icmp_reader)
t_icmp_reader.setDaemon(True)
t_icmp_reader.start()

while True:
	try:
		#Should we send the packet from stdin_reader or an empty one?
		if not PACKET_EMPTY.isSet():
			#Useful Packet
			line_slice = PACKET[0:55]
			PACKET = PACKET[55:]
			pkt = IP(dst=IP_DST)/ICMP(type=8)/Raw("a" + line_slice)
			send(pkt, verbose=False)
			
			if len(PACKET) == 0:
				PACKET_EMPTY.set()
		
		else:
			#Empty Packet
			pkt = IP(dst=IP_DST)/ICMP(type=8)/Raw("b")
			send(pkt, verbose=False)
		
		time.sleep(PING_INTERVAL)
	
	except KeyboardInterrupt:
		break
