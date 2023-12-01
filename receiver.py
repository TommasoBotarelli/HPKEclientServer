import socket
import json
from functions import *
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMInterface
from threading import Thread

f = open('receiver_data.json')
receiver_data = json.load(f)

# ALL OPTIONAL parameters for mode
my_sk = None # type: KEMKeyInterface, sks o skr, KEM sender/receiver private key
eks = None # type: KEMKeyPair, ephemereal key
psk = receiver_data["psk"] if "psk" in receiver_data else "" # a pre-shared key held by both the sender and the receiver
psk_id = receiver_data["psk_id"] if "psk_id" in receiver_data else ""# an identifier for the PSK
ikm = bytes.fromhex(receiver_data["ikm"]) if "ikm" in receiver_data else b"" # optional, can be different for sender and receiver
my_info = receiver_data["info"] if "info" in receiver_data else "" # application-supplied information
my_aad = receiver_data["aad"] if "aad" in receiver_data else "" # can be used for seal and open along with info

print("------------- Io sono il RECEIVER -------------")
# HOST = "::1"  # Standard loopback interface address (localhost)
PORT = 1024  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # the connection is established
    HOST = socket.gethostbyname(socket.gethostname())
    print('IP address: ' + HOST)
    print('Porta: ' + str(PORT))
    print('Attendo una connessione...')
    s.settimeout(60)
    s.bind((HOST, PORT))
    s.listen()

    conn, addr = s.accept()

    with conn:
        #print(f"Connected by {addr}")

        condition = True
        while condition:
            conn.sendall(b'ACK')
            in_message = conn.recv(1024).decode()
            if in_message == 'OK':
                print('Connessione stabilita in modo corretto')
                print('Inserisci Q per chiudere la connessione')
                condition = False
        
        # configuration data for hpke are received
        config_pk_sender = conn.recv(2048).decode()
        config_pk_sender = json.loads(config_pk_sender)
        #print("Dati di configurazione: ")
        #print(config_pk_sender)

        s.settimeout(60)
        
        # Cipher suite for receiver is created
        suite_r = CipherSuite.new(
            KEMId(config_pk_sender["KEMid"]),
            KDFId(config_pk_sender["KDFid"]),
            AEADId(config_pk_sender["AEADid"])
        )
        
        # the public-private key pair is generated
        keypair = suite_r.kem.derive_key_pair(ikm)

        # your public key is sent
        my_pk = keypair.public_key
        my_sk = keypair.private_key
        conn.sendall(my_pk.to_public_bytes())
        
        # the other public key is received
        sender_pk = conn.recv(1024)
        s.settimeout(60)
        sender_pk = suite_r.kem.deserialize_public_key(sender_pk)
        
        # send additional data
        hpke_data = {
            "other_info": my_info,
            "other_aad": my_aad,
        }
        conn.sendall(json.dumps(hpke_data).encode())
        # receive additional data
        other_hpke_data = conn.recv(2048).decode()
        other_hpke_data = json.loads(other_hpke_data)
        
        # encode in bytes of other data
        my_info = bytes.fromhex(my_info)
        my_aad = bytes.fromhex(my_aad)
        psk = bytes.fromhex(psk)
        psk_id = bytes.fromhex(psk_id)
        other_info = bytes.fromhex(other_hpke_data["other_info"])
        other_aad = bytes.fromhex(other_hpke_data["other_aad"])
        
        # the other serialized public key is received
        other_enc = conn.recv(2048)
        
        # the context to receive data is created
        receiving = suite_r.create_recipient_context(other_enc, my_sk, other_info, sender_pk, psk, psk_id)
        
        # the context to send data is created
        my_enc, sending = suite_r.create_sender_context(sender_pk, my_info, my_sk, psk, psk_id, eks)
        conn.sendall(my_enc)
        
        outMessageThread = Thread(target = sendMessage, args = (conn, sending, my_aad))
        outMessageThread.start()
    
        inMessageThread = Thread(target = getMessage, args = (conn, receiving, sending, my_aad, other_aad))
        inMessageThread.start()

        inMessageThread.join()
        outMessageThread.join()

        conn.close()
        s.close()
