#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Date    : 2014-09-30 13:24:18
# @Author  : Robin
# @Link    : https://github.com/sintrb/openwrt-http-hijack

import pcap
import dpkt
import re


def retext(p, s, d):
	res = re.findall(p,s)
	return res[0] if res else d

def rehead(data):
	p = retext('GET (\S+) HTTP/', data, None)
	h = retext('Host:\s*(\S+)\s*', data, None)
	c = retext('Cookie:(.*)\n', data, None)
	return (h,p,c)

def record(url, cookie):
	pass

pc=pcap.pcap('eth0')
pc.setfilter('tcp dst port 80')
for t, d in pc:
	eth = dpkt.ethernet.Ethernet(d)
	if eth.data.__class__.__name__ == 'IP':
		ip = eth.data
		if ip.data.__class__.__name__ == 'TCP':
			tcp = ip.data
			data = tcp.data
			if len(data) and 'HTTP' in data:
				ps = rehead(data)
				if ps[0] and ps[1]:
					url = ''
					if tcp.dport==80:
						url = 'http://%s%s'%(ps[0], ps[1])
					else:
						url = 'http://%s%s:%d'%(ps[0],tcp.dport, ps[1])
					ck = ps[2]
					if ck:
						record(url, ck)
						print url, ck
					else:
						print url


