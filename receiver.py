import socket
import json
from functions import *
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMInterface
from threading import Thread

print("------------- Io sono il RECEIVER -------------")
# HOST = "::1"  # Standard loopback interface address (localhost)
PORT = 1024  # Port to listen on (non-privileged ports are > 1023)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    HOST = socket.gethostbyname(socket.gethostname())
    print('IP address: ' + HOST)
    print('Porta: ' + str(PORT))
    print('Attendo una connessione...')
    s.settimeout(60)
    s.bind((HOST, PORT))
    s.listen()

    conn, addr = s.accept()

    with conn:
        print(f"Connected by {addr}")

        condition = True
        while condition:
            conn.sendall(b'ACK')
            in_message = conn.recv(1024).decode()
            if in_message == 'OK':
                print('Connessione stabilita in modo corretto')
                condition = False

        config_pk_sender = conn.recv(2048).decode()
        config_pk_sender = json.loads(config_pk_sender)
        print("Dati di configurazione: ")
        print(config_pk_sender)

        s.settimeout(60)
        
        suite_r = CipherSuite.new(
            KEMId(config_pk_sender["KEMid"]),
            KDFId(config_pk_sender["KDFid"]),
            AEADId(config_pk_sender["AEADid"])
        )

        keypair = suite_r.kem.derive_key_pair(b"")

        my_pk = keypair.public_key
        conn.sendall(my_pk.to_public_bytes())
        sender_pk = conn.recv(1024)
        
        sender_pk = suite_r.kem.deserialize_public_key(sender_pk)
        
        other_enc = conn.recv(2048)
        
        my_sk = keypair.private_key
        receiving = suite_r.create_recipient_context(other_enc, my_sk)

        my_enc, sending = suite_r.create_sender_context(sender_pk)
        conn.sendall(my_enc)
        s.settimeout(60)

        outMessageThread = Thread(target = sendMessage, args = (conn, sending))
        outMessageThread.start()
    
        inMessageThread = Thread(target = getMessage, args = (conn, receiving, sending))
        inMessageThread.start()

        inMessageThread.join()
        outMessageThread.join()

        conn.close()
        s.close()




