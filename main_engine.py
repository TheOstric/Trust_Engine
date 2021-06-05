from socket import socket, AF_INET, SOCK_DGRAM
import threading
import trust_engine
import os
import time
import datetime

now = time.localtime()
c_time = datetime.datetime(now[0],now[1],now[2],now[3],now[4],now[5]).timestamp()
time_stamp = int(time.time())
print(time_stamp)
devices = []

if os.path.exists('./addresses.txt') and os.path.getsize('./addresses.txt') > 0:
    with open('./addresses.txt') as addrs:
        lines = addrs.readlines()
        l3 = lines[2].split()
        l2 = lines[1].split()

        UDP_IP = l3[1]
        UDP_PORT = int(l3[3])

        IP = l2[1]
        PORT_NUM = int(l2[3])

if os.path.exists('./config.txt') and os.path.getsize('./config.txt') > 0:
    with open('./config.txt') as config:
        lines = config.readlines()
        time_interval = int(lines[-1].split()[1])
        key = lines[-9].split()[1]

sendSocket = socket(AF_INET,SOCK_DGRAM)

with socket(AF_INET,SOCK_DGRAM) as recSocket:
    recSocket.bind((UDP_IP,UDP_PORT))
    i = 0
    requests = []
    lock = threading.Lock()
    condition = threading.Condition(lock)

    t = trust_engine.TrustEngine(lock,requests,condition)
    t.start()
    while True:
        data = recSocket.recv(1024)

        request = data.decode()
        single_device = request.split()[2]

        ctime = time.localtime()
        c_time = datetime.datetime(ctime[0],ctime[1],ctime[2],ctime[3],ctime[4],ctime[5]).timestamp()
        print(c_time)
        print(time_stamp)
        if int(c_time) - int(time_stamp) > time_interval:
            diff_time = (int(c_time) - int(time_stamp)) % time_interval
            time_stamp += (time_interval * diff_time)
            devices.clear()

        if devices.count(single_device) == 0:
            devices.append(single_device)
            lock.acquire()
            requests.append(request)

            if len(requests) == 1:
                condition.notify()
    
            lock.release()

        else:
            sendSocket.sendto(str.encode('Allowed' + key),(IP,PORT_NUM))

sendSocket.close()
