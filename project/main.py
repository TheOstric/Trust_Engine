from flask import Flask, render_template, redirect, url_for, request, flash
from flask_mail import Mail, Message
from textmagic.rest import TextmagicRestClient
from socket import socket, AF_INET, SOCK_DGRAM
import os
import json
import pyotp
import hashlib
import socket
import pipes
import portalocker
import trust_engine
import concurrent.futures

risk_level = 0
user_level = 0
risk = ''
ip = ''
host = ''
data = ''
r = ''
confirmed = False
db_item = {}
username = ""
token = ""
client = TextmagicRestClient(username, token)
app = Flask(__name__)

random_key = os.urandom(16)
app.config.update(dict(
    DEBUG = True,
    SECRET_KEY = str(random_key),
    MAIL_SERVER = "",
    MAIL_PORT = "port number for mail service",
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
    MAIL_USERNAME = "",
    MAIL_PASSWORD = "",
))
hfun = 'sha256'
mail = Mail(app)

def check_credentials(email, password, level):

    global db_item
    if len(db_item) == 0:
        if os.path.exists('./auth.json') and os.path.getsize('./auth.json') > 0:
            with open('./auth.json','r') as json_file:
                db_item = json.load(json_file)
        else:
            return "Not in the database"

    if email not in db_item:
        print(db_item)
        return "Not in the database"
    else:
        salt = db_item.get(email).get('salt')
        hashed = db_item.get(email).get('hashed')
        shashed = hashlib.pbkdf2_hmac(hfun, password.encode(), salt.encode(), 100000)
        if hashed == shashed.hex():
            if db_item[email]["level"] == level:
                return "True"
            else:
                return "Wrong user level"
        else:
            
            return "False"

def identify_level(risk_host, risk_user):
    global risk_level
    print(risk_host + ' ' + str(risk_user))
    if risk_host == 'Low' and risk_user == 0:
        return 0
    
    if risk_host == 'Low' and risk_user == 1:
        return 1
    
    if risk_host == 'Medium' and risk_user == 0:
        return 1

    if risk_host == 'Medium' and risk_user == 1:
        return 2

    if risk_host == 'High' and risk_user == 0:
        return 2

    if risk_host == 'High' and risk_user == 1:
        return 3


@app.route("/", methods = ["POST","GET"])
def home():
    global r, host, ip, confirmed, risk
    print('CONFIRMED: ' + str(confirmed))
    if confirmed == False:
        if request.method == 'GET':
            return render_template("index.html")
        else:
            data = request.get_data(False,True,False).split()
            print(data)
            risk = data[3]
            print('RISK ' + risk)
            ip = data[2]
            r = data[0] + ' ' + data[1] + ' ' + data[2]
            host = data[1]
            return render_template("index.html")
    else:
        confirmed = False
        return redirect('https://' + host)

@app.route("/pass_auth")
def pass_auth():
    global user_level

    user_level = 0
    return render_template("pass_auth.html")

@app.route('/pass_auth', methods=['POST'])
def login():
    global r, host, ip, risk, risk_level, confirmed, user_level

    email = request.form.get("email")
    print(email)
    password = request.form.get("password")
    
    result = check_credentials(email,password)
    if result == "True":
        risk_level = identify_level(risk,user_level)
        print(risk_level)
        if risk_level == 0:
            t = trust_engine.TrustEngine()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(t.run,r)
                print(future.result())
                if future.result() == 'Allowed':
                    confirmed = True
                    return render_template('authorized.html')
                else:
                    return render_template('unauthorized.html')
            
        elif risk_level == 1:
            return redirect('http://127.0.0.1:5000/pass_auth/2fa')
        elif risk_level == 2:
            return redirect('http://127.0.0.1/pass_auth/email_a')
    else:

        if result == "False":
            message = 'Please check your login details and try again.'
        elif result == "Not in the database":
            message = 'Your credentials are not in the database, please first register to the system.'
        elif result == "Wrong user level":
            message = 'Your credentials correspond to different user level. Please, check another user level for the login.'
            flash(message)
            return redirect('http://127.0.0.1:5000/')
        flash(message)
        return redirect('http://127.0.0.1:5000/pass_auth')

@app.route('/pass_auth_admin', methods=['POST', 'GET'])
def login_admin():
    global r, host, ip, risk, risk_level, confirmed, user_level

    user_level = 1
    email = request.form.get("email")
    print(email)
    password = request.form.get("password")
    result = check_credentials(email,password)
    if result == "True":
        risk_level = identify_level(risk,user_level)
        print(risk_level)
        if risk_level == 0:
            t = trust_engine.TrustEngine()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(t.run,r)
                print(future.result())
                if future.result() == 'Allowed':
                    confirmed = True
                    return render_template('authorized.html')
                else:
                    return render_template('unauthorized.html')
            
        elif risk_level == 1:
            return redirect('http://127.0.0.1:5000/pass_auth/2fa')
        elif risk_level == 2:
            return redirect('http://127.0.0.1/pass_auth/email_a')
    else:
        if result == "False":
            message = 'Please check your login details and try again.'
        elif result == "Not in the database":
            message = 'Your credentials are not in the database, please first register to the system.'
        elif result == "Wrong user level":
            message = 'Your credentials correspond to different user level. Please, check another user level for the login.'
            flash(message)
            return redirect('http://127.0.0.1:5000/')
        flash(message)
        return redirect('http://127.0.0.1:5000/pass_auth')

@app.route('/pass_auth/2fa')
def login_email():
    #generating random token for authentication
    token = pyotp.random_base32()

    msg = Message('Authentication mail with token',sender = '', recipients=[''])
    link = url_for('confirm',external = True)
    msg.body = token
    mail.send(msg)

    return render_template("login_email.html", secret = token)

@app.route('/pass_auth/2fa', methods=["POST", "GET"])
def login_email_auth():
    #getting secret Token used by user
    token = request.form.get('secret')
    #getting OTP generated by GoogleAuth
    otp = request.form.get('otp')
    if otp == '':
        flash("Please, submit a not empty otp","danger")
        return redirect(url_for("login_email"))
    
    otp_check = int(otp)

    #verifying OTP with PyOTP
    if pyotp.TOTP(token).verify(otp_check):
        #OTP is valid
        flash("The submitted OTP token is valid","success")
        return redirect('https://' + host)
    else:
        #OTP is invalid
        flash("The OTP submitted token is invalid","danger")
        return redirect(url_for("login_email"))

@app.route('/pass_auth/email_a')
def login_sms():
    msg = Message('Authentication mail with token',sender = '', recipients=[''])
    link = url_for('confirm',external = True)
    msg.body = 'Please, click on the following link and then check your phone for the authentication code: {}'.format(link)
    mail.send(msg)

    flash("Check your email and use the authentication link","success")
    return render_template('pass_auth.html')

@app.route('/pass_auth/sms_a')
def confirm():
    msg = client.messages.create(phones= "", text = "12345")
    return render_template("login_email.html")

if __name__ == '__main__':
    app.run(debug=True)
