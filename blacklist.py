import json
import os
import time
import calendar

class Blacklist:
    #The aim of this class is to check if the device that is attempting to connect to the system 
    #was previously added to the blacklist and its connection attempt must be rejected immediately,
    #or if the device has to be added to the blacklist
    black_items = {}

    #initialize the black_items data structure with the data in blacklist.json file
    def __init__ (self):
        if(os.path.exists('./blacklist.json')) and os.path.getsize('./blacklist.json') > 0:
            with open('./blacklist.json','r') as json_file:
                self.black_items = json.load(json_file)

    #function used to check if the device has been added in the blacklist and if it has to be removed from it
    #because the amount of time passed with the argument LIMIT has been expired
    def blist_check_update(self,IP,LIMIT):
        if len(self.black_items) > 0:
            if(self.black_items.get(IP) != None):
                if(int(time.time()) - int(self.black_items[IP].get("insertion_s_time")) > int(LIMIT)):
                    self.black_items.pop(IP)

                    #if the device can be removed from the list, the blacklist.json file is updated with the new verion of the data structure
                    with open('./blacklist.json','w') as json_file:
                        json.dump(self.black_items,json_file)
                    return 'None'
                else:
                    return 'Denied'
        else:
            return 'None'

    #function used to update the blacklist.json file with the new version of the black_items data structure, whenever a new device is added to the blacklist
    def blist_update(self,IP):
        #ctime -> current_time expressed in yyyy/mm/dd hh:mm:ss
        ctime = time.localtime()
        self.black_items[IP] = {
            'insertion_time' : calendar.day_name[ctime[6]] + ', ' + str(ctime[0]) + '/' + str(ctime[1]) + '/' + str(ctime[2]) + ' ' + str(ctime[3]) + ':' + str(ctime[4]) + ':' + str(ctime[5]),
            'insertion_s_time' : time.time()
        }

        with open('./blacklist.json','w') as json_file:
            json.dump(self.black_items,json_file)
