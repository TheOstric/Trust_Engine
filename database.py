import os
import json

class Database:

#the elements in the database are:
#-ID_DEVICE -> the identifier
#-DESTINATION_SERVICE -> the type of service to which you want to connect the device
#-SUCCESS_PROBABILITY -> the probability of success of a possible attack, initiated by the connected device
#-TIME_REQUIRED -> the time required for the hypothetical attack
#-GOAL_ACHIEVED -> the goal achieved with the attack

    db_item = {}
    count = 0

    def __init__(self):
        if os.path.exists('./database.json') and os.path.getsize('./database.json') > 0:
            with open('./database.json','r') as json_file:
                self.db_item = json.load(json_file)

    def db_check(self,INITIAL_RIGHTS,SERVICE_REQUIRED,GOALS_LIST):
        #filetered version of the dictionary db_item, containing only the items in which the ID_DEVICE field is equals to 
        #the ID_DEVICE passed as argument (the ID_DEVICE of the device that is attempting to connect)
        #and the DESTINATION_SERVICE is equals to SERVICE_REQUIRED
        target_db = {k: v for k, v in self.db_item.items() if v.get("initial_rights") == INITIAL_RIGHTS}

        if target_db != None:
            filtered_db_item = {k: v for k, v in target_db.items() if SERVICE_REQUIRED in v }

            if(len(filtered_db_item) > 0):
                for k, v in filtered_db_item.items():
                    #if there is an entry in the GOALS_LIST dictionary whose key is equals to the GOAL_ACHIEVED field 
                    #in the current entry of the filtered dictionary, there are needed controls about thresholds specified in the GOALS_LIST
                    check = GOALS_LIST.get(v.get("goal_achieved"))
                    if(check != None):
                        #the difference in those two if statements is that:
                        #in the first one, the boolean operator chosed to check the thresholds is an and
                        #meanwhile, in the second one is an or
                        #(the decision has been written in the AND_OR field of GOALS_LIST)
                        if check.get("and_or") == str(0):
                            if(check.get("max_prob") > v.get(SERVICE_REQUIRED).get("success_probability") and check.get("min_time") < v.get(SERVICE_REQUIRED).get("time_required")):
                                return 'Connection autorized'
                            elif(check.get("max_prob") <= v.get(SERVICE_REQUIRED).get("success_probability")):
                                return 'Success probability upper than the threshold'
                            else:
                                return 'Success time required lower than the threshold'
                        else:
                            if(check.get("max_prob") > v.get(SERVICE_REQUIRED).get("success_probability") or check.get("min_time") < v.get(SERVICE_REQUIRED).get("time_required")):
                                return 'Connection autorized'
                            else:
                                return 'Success probability too high and time required too low'
                    else:
                        return 'Thresholds not specified'
            else:
                return 'Connection autorized'
        else:
            return 'Connection autorized'
                