import json
import os
import time
import calendar

#The aim of this class is to save the information about a device and its connection attempt in a JSON file
class Log:

    log_items = {}
    num = 0

    def __init__(self):
        if os.path.exists('./log.json') and os.path.getsize('./log.json') > 0:
            with open('log.json','r') as json_file:
                self.log_items = json.load(json_file)
        self.num = len(self.log_items)
    
    def save_on_log(self,IP_ADDRESS,GOAL,OUTCOME,OUTCOME_REASON):
        #ctime -> current_time expressed in yyyy/mm/dd hh:mm:ss
        ctime = time.localtime()
        self.log_items['device' + str(self.num)] = {
            'ip_address' : IP_ADDRESS,
            'time_stamp' : calendar.day_name[ctime[6]] + ', ' + str(ctime[0]) + '/' + str(ctime[1]) + '/' + str(ctime[2]) + ' ' + str(ctime[3]) + ':' + str(ctime[4]) + ':' + str(ctime[5]),
            'service_to_reach' : GOAL,
            'outcome' : OUTCOME,
            'outcome_reason' : OUTCOME_REASON,
            'time_s_stamp' : time.time()
        }
        self.num += 1
        list_items = self.log_items.items()

        with open('log.json','w') as json_file:
            json.dump(self.log_items,json_file)

    #method to check if a device is trying to connect to the system and the number of its past attempts overcomes the estabilished limits 
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
    