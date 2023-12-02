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
kemID = sender_data["kem_id"] if "kem_id" in sender_data else  16 # ID of KEM algorithm used
kdfID = sender_data["kdf_id"] if "kdf_id" in sender_data else 1 # ID of KDF algorithm used
aeadID = sender_data["aead_id"] if "aead_id" in sender_data else 3 # ID of AEAD algorithm used

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
ikm = bytes.fromhex(sender_data["ikm"]) if "ikm" in sender_data else b"" # used for keys generation, can be different for sender and receiver
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
    my_info = bytes.fromhex(my_info)
    my_aad = bytes.fromhex(my_aad)
    psk = bytes.fromhex(psk)
    psk_id = bytes.fromhex(psk_id)
    other_info = bytes.fromhex(other_hpke_data["other_info"])
    other_aad = bytes.fromhex(other_hpke_data["other_aad"])

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

