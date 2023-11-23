import socket
import json
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMInterface
from threading import Thread

print("------------- Io sono il RECEIVER -------------")
# HOST = "::1"  # Standard loopback interface address (localhost)
PORT = 1024  # Port to listen on (non-privileged ports are > 1023)

x = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
y = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"


def sendMessage(sk):
    while True:
        message = input()
        sk.sendall(message.encode())


def getMessage(sk):
    while True:
        inMessage = sk.recv(1024).decode()
        print(f'IN: {inMessage}')


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

        send = False
        message_out = ''

        outMessageThread = Thread(target=sendMessage, args=(conn,))
        outMessageThread.start()

        inMessageThread = Thread(target=getMessage, args=(conn,))
        inMessageThread.start()

        outMessageThread.join()
        inMessageThread.join()

        while True:
            if send:
                message_out = input('Scrivi messaggio | chiudi connessione (q) | attendi (d): ')
            else:
                print('Aspetto un messaggio...')
                in_message = conn.recv(2048)
                print("DECIFRO...")
                in_message = receiving.open(in_message).decode()
                if in_message == 'WAITING':
                    send = True
                elif in_message == 'CLOSING':
                    conn.close()
                    s.close()
                    print('Chiudo la connessione')
                    break
                print('Ho ricevuto il messaggio: ' + in_message)
                message_out = ''

            if message_out.upper() == 'q'.upper():
                print('Chiudo la connessione')
                conn.sendall(sending.seal('CLOSING'.encode()))
                conn.close()
                s.close()
                break
            elif message_out.upper() == 'd'.upper():
                #print('Mi metto in attesa')
                conn.sendall(sending.seal('WAITING'.encode()))
                send = False
            elif send:
                #print('Invio messaggio')
                if message_out != '':
                    print("CIFRO...")
                    conn.sendall(sending.seal(message_out.encode()))
                else:
                    conn.sendall(message_out.encode())
