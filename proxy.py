from mitmproxy import http
from socket import socket, AF_INET, SOCK_DGRAM
from mitmproxy.script import concurrent
from threading import Lock, Condition
import socket
from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
import os
import ssl
import time
import parser
import mitmproxy.http
import sys
import requests
import pipes
import portalocker
import datetime
import proxy_worker

pipe = pipes.Template()

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


domain_names = {}

class MyProxy:

    def __init__(self):
        super().__init__()

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
                self.max_attempts = int(lines[-5].split()[1])
                udp_timeout = int(lines[-3].split()[1])
                time_interval = int(lines[-1].split()[1])
                parsing = lines[-7].split()[1]
                key = lines[-9].split()[1]

        if parsing == "y":
            pars = parser.Parser()
            pars.parse()

        self.devices = {}
        self.lock = Lock()
        udpSoc = socket.socket(AF_INET,SOCK_DGRAM)
        self.worker = proxy_worker.ProxyWorker(self.lock,self.devices)
        self.worker.start()

    #function used to check which is the risk level associated to a certain host from the system administrator
    #if no risk level was found, the function will return the highest level possible 
    def check_risklevel(self, host):
        if(os.path.exists('./risk_levels.txt')) and os.path.getsize('./risk_levels.txt') > 0:
            with open('./risk_levels.txt') as risk:
                    for line in risk:
                        if host == line.split()[0]:
                            return line.split()[1]
                    return "High"
        else:
            return "High"

    def services_parses(self,domain_name):
        
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

    @concurrent
    def request(self,flow: http.HTTPFlow) -> None:

        global time_stamp

        host = flow.request.host
        address = flow.client_conn.ip_address[0]
        print('HOST ' + host)
        #if (and only if) the host required by the device it's one of the hosts of the organization, contact the trust engine
        if self.services_parses(host) :
            print(self.services_parses(host))
            self.lock.acquire()
            if address.split(':')[3] not in self.devices:
                self.lock.release()
                with portalocker.Lock('./project/pipefile') as file:
                    file.seek(0)
                    file.write('http ' + host + ' ' + address.split(':')[3] + ' ' + self.check_risklevel(host))
    
                flow.request.host = 'localhost'
                flow.request.port = 5000
                flow.request.scheme = 'http'
                flow.request.headers["Host"] = "localhost"
                flow.request.set_content("/".encode())
            else:
                self.lock.release()
        

addon = MyProxy()           

opts = options.Options(listen_host=LISTEN_HOST, listen_port=8080)
pconf = proxy.config.ProxyConfig(opts)
m = DumpMaster(opts)
m.server = proxy.server.ProxyServer(pconf)
m.addons.add(addon)
try:
    m.run()

except KeyboardInterrupt:
    m.shutdown()

