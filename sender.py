import socket
import json
import random
from functions import *
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMInterface
from threading import Thread

f = open('sender_data.json')
sender_data = json.load(f)
# Only these = mode_base
# See section A. 5 of the RFC for test vectors
kemID = int(sender_data["kemID"], 16) if "kemID" in sender_data else  0x0010 # ID of KEM algorithm used
kdfID = int(sender_data["kdfID"], 16) if "kdfID" in sender_data else 0x0001 # ID of KDF algorithm used
aeadID = int(sender_data["aeadID"], 16) if "aeadID" in sender_data else 0x0003 # ID of AEAD algorithm used

# Set in JSON file:
#DHKEM_P256_HKDF_SHA256 = 0x0010
#HKDF_SHA256 = 0x0001
#CHACHA20_POLY1305 = 0x0003

# ALL OPTIONAL parameters for mode
my_info = sender_data["info"] if "info" in sender_data else "" # application-supplied information
my_sk = None # type: KEMKeyInterface, sks o skr, KEM sender/receiver private key
psk = sender_data["psk"] if "psk" in sender_data else "" # a pre-shared key held by both the sender and the receiver
psk_id = sender_data["psk_id"] if "psk_id" in sender_data else "" # an identifier for the PSK
eks = None # type: KEMKeyPair, ephemereal key
ikm = sender_data["ikm"].encode() if "ikm" in sender_data else b"" # used for keys generation, can be different for sender and receiver
my_aad = sender_data["aad"] if "aad" in sender_data else "" # can be used for seal and open along with info

print("------------- Io sono il SENDER -------------")
HOST = input("Inserisci IP del receiver: ")
PORT = int(input("Inserisci porta del receiver: "))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # the connection is established
    s.connect((HOST, PORT))
    s.settimeout(5)
    condition = True

    count = 0
    max_test = 10

    while condition:
        data = s.recv(1024)
        if data.decode('utf-8') == 'ACK':
            print('Possiamo iniziare a scambiarci messaggi')
            print('Inserisci Q per chiudere la connessione')
            to_server = 'OK'
            condition = False
            s.sendall(to_server.encode())
        # if the connection is not successful, we try to re-establish it
        elif data.decode('utf-8') != 'ACK' and count < max_test:
            print('Riprovo a connettermi')
            to_server = 'KO'
            s.sendall(to_server.encode())
            count += 1
        else:
            s.close()
    
    # configuration data for hpke are sent
    config_message_to_server = {
        "KEMid": kemID,
        "KDFid": kdfID,
        "AEADid": aeadID,
    }

    message_to_server = json.dumps(config_message_to_server)
    s.sendall(message_to_server.encode())
    
    # Cipher suite for sender is created
    suite_s = CipherSuite.new(
        KEMId(kemID),
        KDFId(kdfID),
        AEADId(aeadID)
    )
    
    # the public-private key pair is generated
    keypair = suite_s.kem.derive_key_pair(ikm)

    # your public key is sent
    my_pk = keypair.public_key
    my_sk = keypair.private_key
    s.sendall(my_pk.to_public_bytes())
    
    # the other public key is received
    receiver_pk = s.recv(1024)
    s.settimeout(60)
    receiver_pk = suite_s.kem.deserialize_public_key(receiver_pk)
    
    # send additional data
    hpke_data = {
        "other_info": my_info,
        "other_aad": my_aad,
    }
    s.sendall(json.dumps(hpke_data).encode())
    # receive additional data
    other_hpke_data = s.recv(2048).decode()
    other_hpke_data = json.loads(other_hpke_data)
    
    # encode in bytes of other data
    my_info = my_info.encode()
    my_aad = my_aad.encode()
    psk = psk.encode()
    psk_id = psk_id.encode()
    other_info = other_hpke_data["other_info"].encode()
    other_aad = other_hpke_data["other_aad"].encode()

    # the context to send data is created
    # enc is the serialized public key
    my_enc, sending = suite_s.create_sender_context(receiver_pk, my_info, my_sk, psk, psk_id, eks)
    s.sendall(my_enc)
    
    # the other serialized public key is received
    other_enc = s.recv(2048)
    
    # the context to receive data is created
    receiving = suite_s.create_recipient_context(other_enc, my_sk, other_info, receiver_pk, psk, psk_id)
    
    outMessageThread = Thread(target = sendMessage, args=(s, sending, my_aad))
    outMessageThread.start()
    
    inMessageThread = Thread(target = getMessage, args=(s, receiving, sending, my_aad, other_aad))
    inMessageThread.start()

    inMessageThread.join()
    outMessageThread.join()

    s.close()

