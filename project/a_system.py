import json
import os
import hashlib

class auth_system():

    db_item = {}
    
    def __init__(self,hfun):
        if os.path.exists('./auth.json') and os.path.getsize('./auth.json') > 0:
            with open('./auth.json','r') as json_file:
                self.db_item = json.load(json_file)
                self.hfun=hfun

    def check_credentials(self, email, password):
        if email not in self.db_item: 
            return False
        else:
            salt = self.db_item.get(email).get('salt')
            hashed = self.db_item.get(email).get('hashed')
            shashed = hashlib.pbkdf2_hmac(self.hfun, password.encode(), salt.encode(), 100000)
            if hashed == shashed.hex():
                return True
            else:
                False
