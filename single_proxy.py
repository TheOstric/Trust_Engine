from mitmproxy import http
import time
from socket import socket, AF_INET, SOCK_DGRAM
import threading

class single_proxy (threading.Thread):

    def __init__(self,flow,flag):
        super(single_proxy, self).__init__()
        self.flow = flow
        self.flag = flag

    def run (self):
        self.request(flow= self.flow)

    def request(self,flow: http.HTTPFlow) -> None:

    #if (and only if) the host required by the device it's one of the hosts of the organization, contact the trust engine
        #print("Thread numero:" + str(threading.get_ident()))
        self.flag == True
        
        flow.resume()
    '''
    c_time = time.time()
    print(time_interval)
    if c_time - time_stamp >= time_interval:
        
        time_stamp += time_interval
        
        address = flow.client_conn.ip_address[0]

        udpSoc.sendto(("http " + flow.request.host + " " + address ).encode(), (IP_SEND,PORT_SEND))

        response = None
        addr = None

        while max_attempts > 0:
            try:
                response, addr = udpResSoc.recvfrom(1024)
                if response.decode() != 'Allowed' or addr[0] != IP_SEND :
                    flow.kill()
                break
            except TimeoutError:
                udpSoc.sendto(("http " + flow.request.host + " " + address ).encode(), (IP_SEND,PORT_SEND))
            max_attempts -= 1
        
        if max_attempts == 0:
            flow.response = http.HTTPResponse.make(status_code=503)
        '''