from mitmproxy import http
import mitmproxy.http
from socket import socket, AF_INET, SOCK_DGRAM
from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.script import concurrent
import os
import ssl
import time
#from dtls import do_patch

#do_patch()

LISTEN_HOST= ''
LISTEN_PORT = 0
IP = ''
PORT = 0
IP_SEND = ''
PORT_SEND = 0
time_interval = 0
time_stamp = 0

def services_parses(domain_name):
    domain_names = {}
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

class MyProxy:

    @concurrent
    def request(self,flow: http.HTTPFlow) -> None:

        #if (and only if) the host required by the device it's one of the hosts of the organization, contact the trust engine
        if services_parses(flow.request.host) == True :
            c_time = time.time()
            if c_time - time_stamp >= time_interval:
                
                time_stamp += time_interval
                
                address = flow.client_conn.ip_address[0]

                udpSoc.sendto(("http " + flow.request.host + " " + address ).encode(), (IP_SEND,PORT_SEND))

                response, addr = udpResSoc.recvfrom(1024)

                if response.decode() != 'Allowed' or addr[0] != IP_SEND :
                    flow.response = http.HTTPResponse.make(status_code=408)

addon = MyProxy()

udpSoc = socket(AF_INET,SOCK_DGRAM)
udpResSoc = socket(AF_INET,SOCK_DGRAM)
#udpSoc = ssl.wrap_socket(socket(AF_INET,SOCK_DGRAM))
#udpResSoc =  ssl.wrap_socket(socket(AF_INET,SOCK_DGRAM))
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
        time_interval = lines[-1].split()[1]

udpResSoc.bind((IP,PORT))

opts = options.Options(listen_host=LISTEN_HOST, listen_port=8080)
pconf = proxy.config.ProxyConfig(opts)
m = DumpMaster(opts)
m.server = proxy.server.ProxyServer(pconf)
m.addons.add(addon)

try:
    m.run()

except KeyboardInterrupt:
    m.shutdown()
        