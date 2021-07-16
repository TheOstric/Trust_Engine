from socket import socket, AF_INET, SOCK_DGRAM
import threading
import os
import time
import datetime

class ProxyWorker (threading.Thread):
    def __init__(self, lock, devices):
        super(ProxyWorker, self).__init__()
        self.lock = lock
        self.devices = devices
        self.max_attempts = 5

        if os.path.exists('./addresses.txt') and os.path.getsize('./addresses.txt') > 0:
            with open('./addresses.txt') as addrs:
                lines = addrs.readlines()
                l2 = lines[1].split()

                IP = l2[1]
                PORT_NUM = int(l2[3])

        self.udpSoc = socket(AF_INET,SOCK_DGRAM)
        self.udpSoc.bind((IP,PORT_NUM))

    def run(self):

        while True:
            while self.max_attempts > 0:
                try:
                    response = self.udpSoc.recv(1024)
                    msg = response.decode().split()
                    device_ip = msg[0]
                    res = msg[1]
                    print('QUI ' + str(msg))
                    if res == 'denied':
                        self.lock.acquire()
                        if device_ip in self.devices:
                            self.devices.pop(self.device_ip)
                        self.lock.release()
                    else:
                        self.now = time.localtime()
                        self.c_time = datetime.datetime(self.now[0],self.now[1],self.now[2],self.now[3],self.now[4],self.now[5]).timestamp()
                        self.lock.acquire()
                        self.devices[device_ip] = str(self.c_time)
                        self.lock.release()
                    break
                except socket.timeout:
                    print(self.max_attempts)
                self.max_attempts -= 1
            
            if self.max_attempts == 0:
                self.lock.acquire()
                if device_ip in self.devices:
                    self.devices.pop(self.device_ip)
                self.lock.release()