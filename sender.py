import socket
import json
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMInterface

kemID = 0x0010
kdfID = 0x0001
aeadID = 0x0003
kid = "01"
kty = "EC"
crv = "P-256"

print("------------- Io sono il SENDER -------------")
HOST = input('Inserisci IP address del receiver: ')
PORT = int(input('Inserisci porta del receiver: '))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.settimeout(5)
    condition = True

    count = 0
    max_test = 10
    
    config_message_to_server = {
        #"KEMid": 0x0010,
        #"KDFid": 0x0001,
        #"AEADid": 0x0003,
        "KEMid": kemID,
        "KDFid": kdfID,
        "AEADid": aeadID,
        "kid": kid,
        "kty": kty,
        "crv": crv,
        "PK_sender": '123456789'
    }

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

    message_to_server = json.dumps(config_message_to_server)
    s.sendall(message_to_server.encode())

    receiver_pk = json.loads(s.recv(1024).decode())
    
    receiver_pk = KEMKey.from_jwk(
        {
            "kid": kid,
            "kty": kty,
            "crv": crv,
            "x": receiver_pk["x"],
            "y": receiver_pk["y"]
        }
    )
    #receiver_pk = s.recv(1024)
    #receiver_pk = KEMInterface.deserialize_public_key(KEMInterface(),key=receiver_pk)
    #print("Chiave pubblica receiver: " + receiver_pk.to_public_bytes())
    s.settimeout(60)
    
    suite_s = CipherSuite.new(
        KEMId(kemID), KDFId(kdfID), AEADId(aeadID)
    )
    enc, sending = suite_s.create_sender_context(receiver_pk)
    s.sendall(enc)
    
    ct = sending.seal(b"Messaggio sicuro!")
    s.sendall(ct)
    
    send = True

    while True:
        if send:
            message_out = input('Scrivi messaggio | chiudi connessione (q) | attendi (d): ')
        else:
            print('Aspetto un messaggio...')
            in_message = s.recv(2048)
            print('Ho ricevuto il messaggio: ' + in_message.decode())
            if in_message.decode() == 'WAITING':
                send = True
            elif in_message.decode() == 'CLOSING':
                s.close()
                print('Chiudo la connessione')
                break
            message_out = ''

        if message_out.upper() == 'q'.upper():
            print('Chiudo la connessione')
            s.sendall(sending.seal('CLOSING'.encode()))
            s.close()
            break
        elif message_out.upper() == 'd'.upper():
            #print('Mi metto in attesa')
            s.sendall(sending.seal('WAITING'.encode()))
            send = False
        elif send:
            #print('Invio messaggio')
            if message_out != '':
                print("CIFRO...")
                s.sendall(sending.seal(message_out.encode()))
            else:
                s.sendall(message_out.encode())

