from dtls import do_patch
from socket import socket, AF_INET, SOCK_DGRAM
import threading
import TrustEngine
import ssl
import os

if(os.path.exists('./addresses.txt')) and os.path.getsize('./addresses.txt') > 0:
    with open('./addresses.txt') as addrs:
        lines = addrs.readlines()
        l3 = lines[2].split()

        UDP_IP = l3[1]
        UDP_PORT = int(l3[3])

do_patch()
with ssl.wrap_socket(socket(AF_INET,SOCK_DGRAM)) as recSocket:
    recSocket.bind((UDP_IP,UDP_PORT))
    i = 0
    requests = {}
    lock = threading.Lock()
    condition = threading.Condition(lock)

    t = TrustEngine.TrustEngine(lock,requests,condition)
    t.start()
    while True:
        data = recSocket.recv(1024)

        request = data.decode()
        lock.acquire()
        requests.update({str(i): request})
        if(len(requests) == 1):
            condition.notify()
        lock.release()

