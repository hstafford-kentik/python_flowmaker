#!/usr/bin/python3

import argparse
import datetime
import signal
import time
import json
import ipaddress

import scapy
from scapy.all import *


parser = argparse.ArgumentParser(description='UDP packets producer with scapy')
parser.add_argument('-c', '--config_file', dest='config_file',
					help='Configuration file path')

args = parser.parse_args()

if args.config_file:
	config_file = args.config_file
else:
	config_file = "./flowmaker.conf"


configfile = open(config_file, 'r')
config = ''
for line in configfile:
	config += re.sub("\#+.*\n", "\n", line)   ## remove comments before trying to parse json.
data = json.loads(config)
print(json.dumps(data, indent=2))	

def clamp(value,max,min):
	if value > max:
		return max
	elif value < min:
		return min
	else:
		return value
		
#Current timestamp in seconds
index = 0
waittime = []
lasttime = []
fpschangetime = []
lastsent = time.time()
logtime = time.time()
flowsSent = {}

for flowdata in data['flows']:
	fpschangetime.append(time.time())
	waittime.append(1.0/float(flowdata['client']['fps_change_interval']))
	lasttime.append(time.time())
	flowsSent[flowdata['client']['name']] = 0


			
tnow = time.time()
pkt = IP(src=data['jazzhands']['srcFlowIP'],dst=data['jazzhands']['destFlowIP'])/UDP(dport=data['jazzhands']['destFlowPort'])/NetflowHeader(version=5)/NetflowHeaderV5(unixSecs=tnow)
flowcount = 0
while True:
	index = 0
	if time.time()-logtime > 10:  # kinda chatty
		logtime = time.time()
		for name in flowsSent.keys():
			print ('Generated '+str(flowsSent[name])+' flows for '+name+' so far.')	
	for flowdata in data['flows']:
		tnow = time.time()
		if tnow-fpschangetime[index] >= flowdata['client']['fps_change_interval']:
			fpschangetime[index] = tnow
			print (index,flowdata['client']['fps_now'],waittime[index])
			flowdata['client']['fps_now'] += random.randint(int(-.01*flowdata['client']['fps_now']*flowdata['client']['fps_variance']),int(.01*flowdata['client']['fps_now']*flowdata['client']['fps_variance']))
			flowdata['client']['fps_now'] = clamp(flowdata['client']['fps_now'],flowdata['client']['fps_max'],flowdata['client']['fps_min'])
			waittime[index] = 1.0/float(flowdata['client']['fps_now'])
			#print (index,flowdata['client']['fps_now'],waittime[index])
		if tnow-lasttime[index] >= waittime[index]:
			flowsSent[flowdata['client']['name']] += 1
			lasttime[index] = tnow
			octets=flowdata['client']['bytes']+random.randint(int(-.01*flowdata['client']['bytes']*int(flowdata['client']['byte_variance'])),int(.01*flowdata['client']['bytes']*int(flowdata['client']['byte_variance'])))
			packets=flowdata['client']['packets']+random.randint(int(-.01*flowdata['client']['packets']*int(flowdata['client']['packet_variance'])),int(.01*flowdata['client']['packets']*int(flowdata['client']['packet_variance'])))			
			destination_cidr = ipaddress.IPv4Network(flowdata['client']['destination_cidr'])
			destination_ip = str(ipaddress.IPv4Address(random.randint(int(destination_cidr.network_address),int(destination_cidr.broadcast_address))))
			source_cidr = ipaddress.IPv4Network(flowdata['client']['source_cidr'])
			source_ip = str(ipaddress.IPv4Address(random.randint(int(source_cidr.network_address),int(source_cidr.broadcast_address))))
			destination_ports = (flowdata['client']['destination_ports']).split('-')
			source_ports = (flowdata['client']['source_ports']).split('-')
			destination_port = random.randint(int(destination_ports[0]),int(destination_ports[1]))
			source_port = random.randint(int(source_ports[0]),int(source_ports[1]))
			#print(destination_ip,source_ip,flowdata['client']['packets'],flowdata['client']['bytes'],destination_port,source_port)
			source_interface = flowdata['client']['source_interface']
			destination_interface = flowdata['client']['destination_interface']
			netflow = NetflowRecordV5(src=source_ip,dst=destination_ip,nexthop="0.0.0.0",input=source_interface,output=destination_interface,\
			dpkts=int(packets),dOctets=int(octets),\
			first=100,last=300,srcport=source_port,\
			dstport=destination_port,pad1=0,tcpFlags=0x00,\
			prot=flowdata['client']['protocol'],tos=0x00,src_as=0,dst_as=0,\
			src_mask=0,dst_mask=0,pad2=0)
			#print(int(packets),int(octets))
			#flowPacket = NetflowHeader(version=5)/NetflowHeaderV5(count=1,unixSecs=tnow)/netflow
			pkt/=netflow
			flowcount += 1
			if 'server' in flowdata:
				octets=flowdata['server']['bytes']+random.randint(int(-.01*flowdata['server']['bytes']*int(flowdata['server']['byte_variance'])),int(.01*flowdata['server']['bytes']*int(flowdata['server']['byte_variance'])))
				packets=flowdata['server']['packets']+random.randint(int(-.01*flowdata['server']['packets']*int(flowdata['server']['packet_variance'])),int(.01*flowdata['server']['packets']*int(flowdata['server']['packet_variance'])))

				netflow = NetflowRecordV5(src=destination_ip,dst=source_ip,nexthop="0.0.0.0",\
				input=2,output=3,dpkts=packets,dOctets=int(octets),\
				first=100,last=300,srcport=destination_port,\
				dstport=source_port,pad1=0,tcpFlags=0x00,\
				prot=flowdata['client']['protocol'],tos=0x00,src_as=0,dst_as=0,\
				src_mask=0,dst_mask=0,pad2=0)
				pkt/=netflow
				flowcount += 1
			if flowcount >= int(data['jazzhands']['maxFlowsPerPacket']) or tnow - lastsent >= int(data['jazzhands']['maxTimeBetweenSending']):				
				send(pkt,verbose=0)
				lastsent = tnow
				flowcount = 0
				pkt = IP(src=data['jazzhands']['srcFlowIP'],dst=data['jazzhands']['destFlowIP'])/UDP(dport=data['jazzhands']['destFlowPort'])/NetflowHeader(version=5)/NetflowHeaderV5(unixSecs=tnow)
		index += 1
exit()	

