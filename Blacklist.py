import json
import os
import time

class Blacklist:
    #The aim of this class is to check if the device that is attempting to connect to the system 
    #was previously added to the blacklist and its connection attempt must be rejected immediately
    black_items = {}

    def __init__ (self):
        black_items= {'-'}

    def blist_check_update(self,IP,LIMIT):
        if(os.path.exists('./blacklist.json')) and os.path.getsize('./blacklist.json') > 0:
            with open('./blacklist.json','r') as json_file:
                self.black_items = json.load(json_file)
            if(self.black_items.get(IP) != None):
                if(int(time.time()) - int(self.black_items[IP].get("insertion_s_time")) > int(LIMIT)):
                    self.black_items.pop(IP)
                    json.dump(self.black_items,json_file)
                    return 'None'
                else:
                    return 'Denied'
        else:
            return 'None'

    def blist_update(self,IP):
        #ctime -> current_time expressed in yyyy/mm/dd hh:mm:ss
        ctime = time.gmtime()
        self.black_items[IP] = {
            'insertion_time' : str(ctime[0]) + '/' + str(ctime[1]) + '/' + str(ctime[2]) + ' ' + str(ctime[3]) + ':' + str(ctime[4]) + ':' + str(ctime[5]),
            'insertion_s_time' : time.time()
        }

        with open('./blacklist.json','w') as json_file:
            json.dump(self.black_items,json_file)
