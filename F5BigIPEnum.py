#!/usr/bin/python
################################
#
#  BigF5 Load Balancer Enumerator
#  
#  Authors: @vimk1ng
#           @m1ndfl4y
#
################################
import ipaddress
import argparse
import requests
import re

repattern = re.compile('(BIGip.*?)=(\d+)\.(\d+)\.\d')

def main():
	requests.packages.urllib3.disable_warnings()
	parser = argparse.ArgumentParser(description='Enumerate BigF5 Load Balancer')
	parser.add_argument('-e', action='store_true', help='Enumerate IPs using empty requests', dest='empty')
	parser.add_argument('-n', help='Enumerate IPs using a specific CIDR range', metavar='CIDR', dest='network')
	parser.add_argument('-a', help='User-Agent header (Default: BigF5Enum)', default='BigF5Enum', dest='agent')
	parser.add_argument('-p', help='Port to enumerate (Default: Gathered from initial request)', dest='port')
	parser.add_argument('host', help='Target host to enumerate')
	args = parser.parse_args()

	if(args.empty and args.network):
		print "Error: You cannot perform empty and network enumeration at the same time!"
		parser.print_help()
		exit(1)

	if(not args.empty and not args.network):
		print "Extracting bigF5 cookie info from {}".format(args.host)
		headers = {'User-Agent': args.agent}
		resp = requests.get(args.host, headers=headers, verify=False, allow_redirects=False)
		foundIP, foundPort, cookieName = decCookie(str(resp.cookies))
		print "Pool Name: {}".format(cookieName[5:])
		print "Found IP: {}, Port: {}".format(foundIP, foundPort)
		exit(0)

	if(args.empty):
		try:
			foundIPArray = []
			print "Using empty request enumeration. Press ^C to quit\n"
			print "Enumerating Backend IPs for: {}".format(args.host)
			headers = {'User-Agent': args.agent}
			resp = requests.get(args.host, headers=headers, verify=False, allow_redirects=False)
			foundIP, foundPort, cookieName = decCookie(str(resp.cookies))
			print "Pool Name: {}".format(cookieName[5:])
			foundIPArray.append(foundIP + ":" + foundPort)
			print "Found IP: {}, Port: {}".format(foundIP, foundPort)
			while True:
				resp = requests.get(args.host, headers=headers, verify=False, allow_redirects=False)
				foundIP, foundPort, cookieName = decCookie(str(resp.cookies))
				foundIPPort = foundIP + ":" + foundPort
				if (foundIPPort not in foundIPArray):
					foundIPArray.append(foundIPPort)
					print "Found IP: {}, Port: {}".format(foundIP, foundPort)
		except KeyboardInterrupt:
			print "\nBigF5Enum Exiting..."
			exit(0)

	if(args.network):
		print "Using network enumeration. Press ^C to quit\n"
		print "Enumerating {} for IPs from {}".format(args.host, args.network)

		if('/' in args.network):
			try:
				enumNetworkCIDR = ipaddress.ip_network(unicode(args.network), strict=False)
			except:
				print "Invalid network address!"
				exit(1)

			headers = {'User-Agent': args.agent}
			resp = requests.get(args.host, headers=headers, verify=False, allow_redirects=False)
			foundIP, foundPort, cookieName = decCookie(str(resp.cookies))
			reqPort = (args.port if args.port else foundPort)
			print "Pool Name: {}".format(cookieName[5:])
			for addr in enumNetworkCIDR:
				headers = {'User-Agent': args.agent, 'Cookie': cookieName + "=" + encCookie(str(addr), reqPort)}
				resp = requests.get(args.host, headers=headers, verify=False, allow_redirects=False)
				if(cookieName not in resp.cookies):
					print "Found IP: {}, Port: {}".format(str(addr), reqPort)

		if('-' in args.network):
			try:
				networkStart, networkEnd = args.network.split('-')
				if(0 < len(networkEnd) <= 3):
					baseOctets = networkStart.split('.')
					baseOctets[3] = networkEnd
					networkEnd = '.'.join(baseOctets)
				enumNetStart = ipaddress.ip_address(unicode(networkStart))
				enumNetEnd = ipaddress.ip_address(unicode(networkEnd))
				enumNetwork = ipaddress.summarize_address_range(enumNetStart, enumNetEnd)
			except:
				print 'Invalid network address!'
				exit(1)

			headers = {'User-Agent': args.agent}
			resp = requests.get(args.host, headers=headers, verify=False, allow_redirects=False)
			foundIP, foundPort, cookieName = decCookie(str(resp.cookies))
			reqPort = (args.port if args.port else foundPort)
			print "Pool Name: {}".format(cookieName[5:])
			for network in enumNetwork:
				for addr in network:
					headers = {'User-Agent': args.agent, 'Cookie': cookieName + "=" + encCookie(str(addr), reqPort)}
					resp = requests.get(args.host, headers=headers, verify=False, allow_redirects=False)
					if(cookieName not in resp.cookies):
						print "Found IP: {}, Port: {}".format(str(addr), reqPort)
		

def decCookie(cookies):
	ipdata = repattern.search(cookies)
	encIP = ipdata.group(2)
	encPort = ipdata.group(3)
	hexIP = '{0:08x}'.format(int(encIP))
	hexIPra = [hexIP[i:i+2] for i in range(0, len(hexIP), 2)][::-1]
	decIP = ".".join([str(int(hexIPra[i], 16)) for i in range(0, len(hexIPra))])
	hexPort = '{0:04x}'.format(int(encPort))
	decPort = int("".join([hexPort[i:i+2] for i in range(0, len(hexPort), 2)][::-1]), 16)
	return str(decIP), str(decPort), ipdata.group(1)

def encCookie(ip, port):
	hexIP = "".join(['{0:02x}'.format(int(i)) for i in ip.split('.')[::-1]])
	encIP = int(hexIP, 16)
	hexPort = '{0:04x}'.format(int(port))
	encPort = int("".join([hexPort[i:i+2] for i in range(0, len(hexPort), 2)][::-1]), 16)
	return str(encIP) + "." + str(encPort) + ".0000"


main()
