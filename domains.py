#!/usr/bin/env python
# coding: utf-8
# By 00theway
import dns.resolver
import threading,nmap,argparse,re,requests,traceback,chardet
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

global ip_ports,ip_domains
ip_ports = {}
ip_domains = {}


class resolvedomain():
	def __init__(self,domains,threads=20):
		self.domains = domains
		self.threads = threads
		self.lock = threading.BoundedSemaphore(value=self.threads)
		self.resolver = dns.resolver.Resolver()
		self.resolver.nameservers = ['114.114.114.114','233.5.5.5']
		self.tasks = []
	
	def lookup(self,domain):
		self.lock.acquire()
		try:
			ips = self.resolver.query(domain)
			addr = ''
			for ip in ips:
				addr = ip.address
				print domain,addr
				if addr in ip_domains:
					ip_domains[addr] += '\n' + domain
				else:
					ip_domains[addr] = domain
		except Exception,e:
			print e
		self.lock.release()
		
	def run(self):
		for domain in self.domains:
			t = threading.Thread(target=self.lookup, args=(domain,))
			self.tasks.append(t)
		for task in self.tasks:
			task.start()
			
		for task in self.tasks:
			task.join()

			
class portscan():
	def __init__(self, ips, ports):
		self.ips = ips
		self.ports = ports
		self.threads = 20
		self.lock = threading.BoundedSemaphore(value=self.threads)
		self.tasks = []

	def port_scan(self, host, ports):
		print 'start scan %s' % host
		ip_ports[host] = 'found no ports'
		banner = ''
		self.lock.acquire()
		try:
			nm = nmap.PortScanner()
			nm.scan(host,','.join(ports))
			for scan_host in nm.all_hosts():
				for port in nm[scan_host]['tcp'].keys():
					if nm[scan_host]['tcp'][port]['state'] == 'open':
						title = 'not found'
						if nm[scan_host]['tcp'][port]['state'] == 'http':
							try:
								html = requests.get("http://%s:%s" % (scan_host,port),timeout=10).content
								charset = chardet.detect(html)['encoding']
								title = re.findall(r'<title>(.*?)</title>', html ,re.IGNORECASE)[0]
								if 'gb' in charset.lower():
									title = title.decode('gbk')
								else:
									title = title.decode('utf-8')
							except:
								pass
						banner += '%d:%s %s\t%s\n' % (port,nm[scan_host]['tcp'][port]['product'],nm[scan_host]['tcp'][port]['version'],title)



		except Exception,e:
			print traceback.print_exc()
			pass
		self.lock.release()
		ip_ports[host] = banner
		print '------',host,ip_ports[host]

	def run(self):
		for ip in self.ips:
			t = threading.Thread(target=self.port_scan, args=(ip, self.ports))
			self.tasks.append(t)
		for task in self.tasks:
			task.start()
			
		for task in self.tasks:
			task.join()
			
			
def main():
	fname = 'huazhu.txt'
	domains = open(fname).read().splitlines()

	
	rdomain = resolvedomain(domains)
	rdomain.run()

	ports = ['21','22','23'
	,'80-90'
	,'443','8443'
	,'8080','8081','8089','8088','8090','8880','8888','9090','9875','9200','9300'
	,'6379'#redis
	,'1433'#sqlserver
	,'3306'#mysql
	,'1521'#oracle
	,'4848'#glassfish
	,'7001'#weblogic
	,'8500'#coldfusion
	,'9060','9043','9080','9043'#websphere
	]
	ips = ip_domains.keys()
	pscan = portscan(ips, ports)
	pscan.run()

	for ip in ip_domains:
		print ip,ip_ports[ip],ip_domains[ip]
		open('%s-ports.txt' % (fname[:-4]),'ab+').write(ip+':\n' + ip_ports[ip] + '\n'+ip_domains[ip]+'\n========================================\n')

if __name__=="__main__":
	main()