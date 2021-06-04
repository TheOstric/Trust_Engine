from socket import socket, AF_INET, SOCK_DGRAM
import json   
import log
import time
import os
import database
import blacklist
import threading
import ssl
from dtls import do_patch
import threading


class TrustEngine (threading.Thread):

    requests = {}

    #
    def __init__(self, lock, requests, condition):
        super(TrustEngine, self).__init__()
        self.requests = requests
        self.lock = lock
        self.condition = condition

    def run(self):
        #The arguments of this program are passed not using the command line, but writing them
        #into a configuration file (named: config.txt) in which the following items must be inserted:
        #-> time_blacklist
        #->chances
        #->goals_list
        #->unknown
        #and into a file named services.txt, in which the various services to which a device could be connected 
        # and their IP addresses must be entered
        
        goals_list = {}
        time_blacklist = 0
        chances = []
        unknown = 0
        key = ''

        #In this loop the file is read and the variables, that will be used to decide the outcome
        #of a connection attempt, are initialized 
        with open('config.txt','r') as config:
            for line in config: #read the file line by line
                if(str.split(line) != []): #if the line isn't blank, check the content and assign the values to the correct variable
                    words = str.split(line)
                    if(words[0] == 'time_blacklist:'):
                        time_blacklist = words[1]
                    elif(words[0] == 'chances:'):
                        chances = [words[1],words[2]]
                        #in this case, another loop is needed because there could be multiple goals
                    elif(words[0] == 'goals_list:'): 
                        l = config.readline()
                        while(str.split(l) != []): 
                            w = str.split(l)
                            goals_list[w[0]] = {
                                'max_prob' : w[1],
                                'min_time' : w[2],
                                'and_or' : w[3]
                            }
                            l = config.readline()
                    elif(words[0] == 'unknown:'):
                        unknown = words[1]
                    if words[0] == 'key':
                        key = words[1]
            

        UDP_IP = ''
        UDP_PORT = 0

        http_thread = False
        http_reqs = {}
        lock = threading.Lock()

        ID_DEVICE = {} #deve essere riempito con l'inventario che descrive le carrattestiche del device che cerca di connettersi

        log_file = log.Log()
        black_file = blacklist.Blacklist()
        db_file = database.Database()

        if(os.path.exists('./addresses.txt')) and os.path.getsize('./addresses.txt') > 0:
            with open('./addresses.txt') as addrs:
                lines = addrs.readlines()
                l3 = lines[2].split()
                l2 = lines[1].split()

                UDP_IP = l3[1]
                UDP_PORT = int(l3[3])

                IP = l2[1]
                PORT_NUM = int(l2[3])

        sendSocket = socket(AF_INET,SOCK_DGRAM)

        while True:

            self.lock.acquire()
            while(len(self.requests) == 0):
                self.condition.wait()

            request = self.requests[0]
            self.requests.remove(request)
            self.lock.release()
            #splitted_request[0] -> type of service
            #splitted_request[1] -> domain name of service
            #splitted_request[2] -> ip of device
            splitted_request = request.split()
            IP_DEVICE = splitted_request[2]

            #the first check made is inside the blacklist, to find out if the device that want to connect 
            #has to be blocked, before doing other controls
            if(black_file.blist_check_update(IP_DEVICE,time_blacklist) != 'None'):
                sendSocket.sendto(str.encode('Connection denied'),(IP,PORT_NUM))
                log_file.save_on_log(IP_DEVICE,splitted_request[1],'Connection denied','Blacklist')
            else:
                #the second check made is inside the log file, to find out if the device has exceeded the limit of allowed attempts
                #in the chosen time interval
                if(log_file.choices_check(IP_DEVICE,chances[1],chances[0]) == 'WARNING'):
                    sendSocket.sendto(str.encode('Connection denied'),(IP,PORT_NUM))
                    black_file.blist_update(IP_DEVICE)
                    log_file.save_on_log(IP_DEVICE,splitted_request[1],'Connection denied','Added in blacklist')
                else:
                    #the third check made is inside the db file, to find out if the values of SUCCESS_PROBABILITY and TIME_REQUIRED
                    #corresponding to the device that is attempting to connect and the service required
                    #respects the thresholds inserted in the configuration file
                    #for all the goals that could be reached by an attack, starting from the device and passing to the service required
                    attempt_result = db_file.db_check(IP,splitted_request[1],goals_list)

                    if (attempt_result != 'Connection autorized'):
                        if attempt_result != 'Thresholds not specified':
                            log_file.save_on_log(IP_DEVICE,splitted_request[1],'Connection denied',attempt_result)
                            sendSocket.sendto(str.encode('Connection denied'),(IP,PORT_NUM))
                        else:
                            log_file.save_on_log(IP_DEVICE,splitted_request[1],'Connection denied',attempt_result)
                            sendSocket.sendto(str.encode('Allowed' + key),(IP,PORT_NUM))
                    else: 
                        #loop in which i parse the text to search for an IP that satisfies 
                        #the request of an http domain sent by the device
                        f = open("HTTPservices.txt","r")
                        for line in f:
                            for word in line.split():
                                if(word == splitted_request[1]):
                                    address = line.split()[1]
                                    log_file.save_on_log(IP_DEVICE,splitted_request[1] + ' ' + address,'Connection allowed','-')
                                    sendSocket.sendto(str.encode('Allowed' + key),(IP,PORT_NUM))
                                    break
                        f.close()
                        #else:
                            #f = open("HTTPservices.txt","r")
                            #partOfRequest = request.split()
                            #for line in f:
                                #for word in line.split():
                                    #if(word == partOfRequest[1]):
                                        #address = line.split()[1]
                                        #print("%s" % address)
                                        
                                        #log_file.save_on_log(IP,request,'Connection allowed','-',)
                                        #sendSocket.sendto(str.encode(address),(IP,PORT_NUM))
                                        #break
                            #f.close()
                    

            
