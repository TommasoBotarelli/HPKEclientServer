import socket
import json
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMInterface

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

    #my_pk = '987654321'

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
        
        my_pk = KEMKey.from_jwk(
            {
                "kid": config_pk_sender["kid"],
                "kty": config_pk_sender["kty"],
                "crv": config_pk_sender["crv"],
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
            }
        )
        
        my_pk_data = {
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        }
        
        # Mi configuro

        #print(my_pk.to_public_bytes())
        conn.sendall(json.dumps(my_pk_data).encode())
        #conn.sendall(my_pk.to_public_bytes())
        s.settimeout(60)
        
        suite_r = CipherSuite.new(
            KEMId(config_pk_sender["KEMid"]), KDFId(config_pk_sender["KDFid"]), AEADId(config_pk_sender["AEADid"])
        )
        enc = conn.recv(2048)
        
        my_sk = KEMKey.from_jwk(
            {
                "kid": config_pk_sender["kid"],
                "kty": config_pk_sender["kty"],
                "crv": config_pk_sender["crv"],
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
            }
        )
        receiving = suite_r.create_recipient_context(enc, my_sk)

        send = False
        message_out = ''

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
                conn.sendall('CLOSING'.encode())
                conn.close()
                s.close()
                break
            elif message_out.upper() == 'd'.upper():
                #print('Mi metto in attesa')
                conn.sendall('WAITING'.encode())
                send = False
            elif send:
                #print('Invio messaggio')
                conn.sendall(message_out.encode())

