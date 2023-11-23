import socket
import json
from functions import *
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMInterface
from threading import Thread


kemID = 0x0010
kdfID = 0x0001
aeadID = 0x0003
info = b""
sks = None # KEMKeyInterface
psk = b""
psk_id = b""
eks = None # KEMKeyPair

print("------------- Io sono il SENDER -------------")
HOST = socket.gethostname()
PORT = 1024

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.settimeout(5)
    condition = True

    count = 0
    max_test = 10

    while condition:
        data = s.recv(1024)
        if data.decode('utf-8') == 'ACK':
            print('Possiamo iniziare a scambiarci messaggi')
            to_server = 'OK'
            condition = False
            s.sendall(to_server.encode())
        elif data.decode('utf-8') != 'ACK' and count < max_test:
            print('Riprovo a connettermi')
            to_server = 'KO'
            s.sendall(to_server.encode())
            count += 1
        else:
            s.close()

    config_message_to_server = {
        "KEMid": kemID,
        "KDFid": kdfID,
        "AEADid": aeadID,
    }
    '''
    "info": info,
    "sks": sks,
    "psk": psk,
    "psk_id": psk_id,
    "eks": eks
    '''

    message_to_server = json.dumps(config_message_to_server)
    s.sendall(message_to_server.encode())
    
    suite_s = CipherSuite.new(
        KEMId(kemID),
        KDFId(kdfID),
        AEADId(aeadID)
    )
    
    keypair = suite_s.kem.derive_key_pair(b"")

    my_pk = keypair.public_key
    s.sendall(my_pk.to_public_bytes())
    receiver_pk = s.recv(1024)

    receiver_pk = suite_s.kem.deserialize_public_key(receiver_pk)

    my_enc, sending = suite_s.create_sender_context(receiver_pk)
    s.sendall(my_enc)
    
    other_enc = s.recv(2048)

    my_sk = keypair.private_key
    receiving = suite_s.create_recipient_context(other_enc, my_sk)
    s.settimeout(60)

    outMessageThread = Thread(target = sendMessage, args=(s, sending))
    outMessageThread.start()
    
    inMessageThread = Thread(target = getMessage, args=(s, receiving))
    inMessageThread.start()

    outMessageThread.join()
    inMessageThread.join()
