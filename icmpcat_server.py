#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import threading
import time

from scapy.all import *

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


def process_packet(pkt):
	global PACKET
	if pkt.haslayer(ICMP):
		if pkt[ICMP].type == 8:
			payload = str(pkt[ICMP].payload)
			if len(payload) > 1:
				if payload[0] == 'a':
					sys.stdout.write(payload[1:])
					sys.stdout.flush()
			
			"""
			This is an ICMP echo-request packet...we will either
			reply to it with data from stdin_reader(), if it's
			ready, or we will reply with an empty ICMP packet.
			"""
			if not PACKET_EMPTY.isSet():
				#Send a useful packet
				line_slice = PACKET[0:55]
				PACKET = PACKET[55:]
				resp_pkt = IP(dst=pkt[IP].src)/ICMP(type=0)/Raw("a" + line_slice)
				send(resp_pkt, verbose=False)
				
				if len(PACKET) == 0:
					PACKET_EMPTY.set()
			
			else:
				#Send an empty packet
				resp_pkt = IP(dst=pkt[IP].src)/ICMP(type=0)/Raw("b")
				send(resp_pkt, verbose=False)

#Spawn a stdin_reader() thread
t_stdin_reader = threading.Thread(target=stdin_reader)
t_stdin_reader.setDaemon(True)
t_stdin_reader.start()

sniff(store=0, prn=process_packet)
