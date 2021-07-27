import socket
import webbrowser
import subprocess

tcpSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

url = input("Inserire il sito web:\n")

webbrowser.open("https://" + url,1)

#tcpSoc.connect(('127.0.0.1',5006))

subprocess.run(["sudo","tpm2_createek","--ek-context", "rsa_ek.ctx", "--key-algorithm" , "rsa", "--public", "rsa_ek.pub"], check=True, text=True)