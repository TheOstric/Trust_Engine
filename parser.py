import json
import os

class Parser():

    def parse(self):

        all_data = {}
        threat_run_details = {}
        threat_plan_sequences = {}
        net_model = {}
        threat_model = {}
        targets = {}
        info_runs = {}

        #associations between IP, ID and IDMainAppEnv
        IPs = {}

        if os.path.exists('./data.json') and os.path.getsize('./data.json') > 0:
            with open('data.json','r') as json_file:
                all_data = json.load(json_file)

            threat_run_details = all_data.get("ThreatRunDetails")
            threat_plan_sequences = all_data.get("ThreatPlanSequences")
            net_model = all_data.get("NetModel")
            threat_model = all_data.get("ThreatModel").get("Agents")
            list_entities = net_model.get("Interfaces")

            for i in range(len(list_entities)):
                IPs[list_entities[i].get("IDMainAppEnv")] = list_entities[i].get("IP")


            ide = 0
            targets = {}
            for i in range(len(threat_model)):
                ide = threat_model[i].get("ID")
                single_agent = threat_model[i].get("Target")

                subtargets = single_agent.get("SubTargets")[0]
                logical_operator = subtargets.get("LogicalOperator")
                rules = subtargets.get("Rules")
                
                target = ""
                for i in range(len(rules)):
                    rights = rules[i].get("RightList")
                    where = rules[i].get("Where")
                    for j in range(len(rights)):
                        target = target + rights[j] + " "
                    for j in range(len(where)):
                        target = target + where[j].get("Item1") + " -> " + where[j].get("Item2") + ", "
                    targets[ide] = target

            run_keys = list(threat_run_details.keys())
            for i in range(len(run_keys)):
                key = run_keys[i]
                runs = threat_run_details.get(str(key))
                for j in range(len(runs)):
                    events = runs[j].get("RunEvents")
                    find = False
                    k = 0
                    while k in range(len(events)) and find == False:
                        id_app = events[k].get("IDAppEnvOrWebUser")
                        if  id_app != None:
                            find = True
                            ip_app = IPs.get(id_app)
                            if info_runs.get(key) != None :
                                if info_runs.get(key).get(ip_app) != None:
                                    if runs[j].get("Successful") == True:

                                        total = info_runs.get(key)[ip_app]["total"] + runs[j].get("Frequency")
                                        
                                        succ = info_runs.get(key)[ip_app]["successful"] + runs[j].get("Frequency")

                                        info_runs.get(key)[ip_app]["successful"] = succ

                                        info_runs.get(key)[ip_app]["total"] = total

                                        info_runs.get(key)[ip_app]["success_probability"] = int((succ / total) * 100)


                                        if runs[j].get("TotalTime") < info_runs.get(key)[ip_app]["time"]:

                                            info_runs.get(key)[ip_app]["time"] = runs[j].get("TotalTime")

                                    else:

                                        info_runs.get(key)[ip_app]["total"] += runs[j].get("Frequency")

                                        info_runs.get(key)[ip_app]["failures"] += runs[j].get("Frequency")

                                else:

                                    succ = 0
                                    fails = 0
                                    total = 0

                                    if runs[j].get("Successful") == True:

                                        succ = runs[j].get("Frequency")

                                    else:
                                        
                                        fails = runs[j].get("Frequency")
                                    
                                    total = succ + fails 
                                    percentage = (succ/total) * 100
                                    info_runs.get(key)[ip_app] = {
                                        "successful" : succ,
                                        "time" : runs[j].get("TotalTime"),
                                        "failures" : fails,
                                        "total" : total,
                                        "success_probability" : int(percentage)
                                    }
                            else:
                                info_runs[key] = {}
                        k += 1

            info_runs_keys = list(info_runs.keys())

            for i in range(len(info_runs_keys)):
                
                goals = info_runs.get(info_runs_keys[i])

                goals_keys = list(goals.keys())

                for j in range(len(goals_keys)):
                    single_goal = goals.get(goals_keys[j])
                    single_goal.pop("successful")
                    single_goal.pop("failures")
                    single_goal.pop("total")

                goals["goal_achieved"] = targets.get(int(info_runs_keys[i]))

            with open('database.json','w') as json_file:
                json_file.drop(info_runs,json_file)
