import socket
import webbrowser
import subprocess
import ssl


def __client():
    context = ssl.create_default_context()

    url = input("Inserire il sito web:\n")

    with socket.create_connection(('127.0.0.1',5006)) as soc:
        with context.wrap_socket(soc) as tcpSoc:
            webbrowser.open("https://" + url,1)

            #receive a message from the proxy to now if the service to reach need a tpm verification or not
            req = tcpSoc.recv(1024)

            if req == 'Not required':
                return

            subprocess.run(["sudo","tpm2_createek","--ek-context", "rsa_ek.ctx", "--key-algorithm" , "rsa", "--public", "rsa_ek.pub"], check=True, text=True)

            subprocess.run(["sudo","tpm2_createak","--ek-context","rsa_ek.ctx","--ak-context","rsa_ak.ctx","--key-algorithm","rsa","--hash-algorithm","sha256","--signing-algorithm","rsassa","--public","rsa_ak.pub","--private","rsa_ak.priv","--ak-name","rsa_ak.name"], check=True, text=True)

'''
            tpm2_quote \
--key-context rsa_ak.ctx \
--pcr-list sha1:0,1,2+sha256:0,1,2 \
--message pcr_quote.plain \
--signature pcr_quote.signature \
--qualification SERVICE_PROVIDER_NONCE \
--hash-algorithm sha256 \
--pcr pcr.bin*/
'''