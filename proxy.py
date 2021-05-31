from mitmproxy import http
from socket import socket, AF_INET, SOCK_DGRAM
import socket
from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.script import concurrent
import os
import ssl
import time
import parser
import mitmproxy.http
from threading import Lock
import sys

LISTEN_HOST= ''
LISTEN_PORT = 0
IP = ''
PORT = 0
IP_SEND = ''
PORT_SEND = 0
udp_timeout = 0
time_stamp = 0
max_attempts = 0
time_interval = 0
parsing = 'n'
key = ''

lock = Lock()

domain_names = {}

def services_parses(domain_name):
    
    if len(domain_names) == 0:
        if(os.path.exists('./HTTPservices.txt')) and os.path.getsize('./HTTPservices.txt') > 0:
            with open('./HTTPservices.txt') as file_s:
                for line in file_s:
                    if domain_names.get(line.split()[0]) == None:
                        domain_names[line.split()[0]] = [line.split()[1]]
                    else:
                        domain_names[line.split()[0]].append(line.split()[1])
    else:
        if domain_names.get(domain_name) != None:
            return True
        else:
            return False

#class MyProxy:

#addon = MyProxy()

udpSoc = socket.socket(AF_INET,SOCK_DGRAM)
udpResSoc = socket.socket(AF_INET,SOCK_DGRAM)

if(os.path.exists('./addresses.txt')) and os.path.getsize('./addresses.txt') > 0:
    with open('./addresses.txt') as addrs:
        lines = addrs.readlines()
        l1 = lines[0].split()
        l2 = lines[1].split()
        l3 = lines[2].split()

        LISTEN_HOST = l1[1]
        LISTEN_PORT = int(l1[3])

        IP = l2[1]
        PORT = int(l2[3])

        IP_SEND = l3[1]
        PORT_SEND = int(l3[3])

if(os.path.exists('./config.txt')) and os.path.getsize('./config.txt') > 0:
    with open('./config.txt') as config:
        lines = config.readlines()
        max_attempts = int(lines[-5].split()[1])
        udp_timeout = int(lines[-3].split()[1])
        time_interval = int(lines[-1].split()[1])
        parsing = lines[-7].split()[1]
        key = lines[-9].split()[1]

if parsing == 'y':
    parser = parser.Parser()
    parser.parse()

udpResSoc.bind((IP,PORT))
udpResSoc.settimeout(udp_timeout)

@concurrent
def request(flow: http.HTTPFlow) -> None:

    global time_stamp, max_attempts

    #if (and only if) the host required by the device it's one of the hosts of the organization, contact the trust engine
    if services_parses(flow.request.host) == True :

        c_time = int(time.time())

        lock.acquire()
        if c_time - time_stamp >= int(time_interval):
            print(c_time - time_stamp)
            if(time_stamp == 0):
                time_stamp = c_time
            else:
                time_stamp += time_interval
            lock.release()

            address = flow.client_conn.ip_address[0]

            udpSoc.sendto(("http " + flow.request.host + " " + address ).encode(), (IP_SEND,PORT_SEND))

            while max_attempts > 0:
                print(max_attempts)
                try:
                    response, addr = udpResSoc.recvfrom(1024)
                    if response.decode() != 'Allowed' + key or addr[0] != IP_SEND :
                        flow.kill()
                    break
                except socket.timeout:
                    udpSoc.sendto(("http " + flow.request.host + " " + address ).encode(), (IP_SEND,PORT_SEND))
                max_attempts -= 1
            
            if max_attempts == 0:
                flow.kill()
        else:
            lock.release()
                
'''
opts = options.Options(listen_host=LISTEN_HOST, listen_port=8080)
pconf = proxy.config.ProxyConfig(opts)
m = DumpMaster(opts)
m.server = proxy.server.ProxyServer(pconf)
m.addons.add(addon)

try:
    m.run()

except KeyboardInterrupt:
    m.shutdown()
'''