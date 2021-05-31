import json
import os
import time
import calendar

#The aim of this class is to save the information about a device and its connection attempt in a JSON file
class Log:

    log_items = {}
    num = 0

    #initialize the log_items data structure with the data in log.json file
    def __init__(self):
        if os.path.exists('./log.json') and os.path.getsize('./log.json') > 0:
            with open('log.json','r') as json_file: 
                self.log_items = json.load(json_file)
        self.num = len(self.log_items)
    
    #function used to record the information about a connection attempt, that are:
    #ip_address -> identifier of the device
    #time_stamp -> time of the attempt expressed in yyyy/mm/dd hh:mm:ss
    #service_to_reach -> destination of the connection
    #outcome -> the attempt's outcome, decreed by the trust engine, after all the necessary checks
    #outcome_reason -> short description of the reason that led to that outcome
    #time_s_stamp -> same time of time_stamp, but expressed in seconds to facilitate the calculations in the choices_check function
    def save_on_log(self,IP_ADDRESS,GOAL,OUTCOME,OUTCOME_REASON):
        #ctime -> current_time expressed in yyyy/mm/dd hh:mm:ss
        ctime = time.localtime()
        stime = int(time.time())
        self.log_items['device' + str(self.num)] = {
            'ip_address' : IP_ADDRESS,
            'time_stamp' : calendar.day_name[ctime[6]] + ', ' + str(ctime[0]) + '/' + str(ctime[1]) + '/' + str(ctime[2]) + ' ' + str(ctime[3]) + ':' + str(ctime[4]) + ':' + str(ctime[5]),
            'service_to_reach' : GOAL,
            'outcome' : OUTCOME,
            'outcome_reason' : OUTCOME_REASON,
            'time_s_stamp' : stime
        }
        self.num += 1
        list_items = self.log_items.items()

        with open('log.json','w') as json_file:
            json.dump(self.log_items,json_file)

    #function used to check if the number of the past attempts of connection overcomes the estabilished limit
    #the limit is expressed with the max amount of attempts a single device can do, during a specific time interval
    #if it overcomes this max amount, the trust engine inserts it in the blacklist
    #the arguments are:
    #IP -> identifies devices in the log file
    #TIME_INTERVAL -> amount of time for the attempts
    #MAX_ATTEMPTS -> max amount of attempts
    def choices_check(self,IP,TIME_INTERVAL,MAX_ATTEMPTS):
        count = 0
        if len(self.log_items) != 0:
            for k,v in self.log_items.items():
                if int(time.time()) - int(v.get("time_s_stamp")) > int(TIME_INTERVAL):
                    break
                else:
                    if v.get("ip_address") == IP and v.get("outcome") == "Connection denied":
                        count += 1

            if(count > int(MAX_ATTEMPTS)):
                return 'WARNING' 
            else:
                return 'OK'
        else:
            return 'OK'
    