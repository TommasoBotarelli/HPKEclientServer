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
HOST = '192.168.56.1'
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
        "kid": kid,
        "kty": kty,
        "crv": crv
    }

    message_to_server = json.dumps(config_message_to_server)
    s.sendall(message_to_server.encode())

    receiver_pk = s.recv(1024)
    s.settimeout(60)

    suite_s = CipherSuite.new(
        KEMId(kemID),
        KDFId(kdfID),
        AEADId(aeadID)
    )

    receiver_pk = suite_s.kem.deserialize_public_key(receiver_pk)

    enc, sending = suite_s.create_sender_context(receiver_pk)
    s.sendall(enc)

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

