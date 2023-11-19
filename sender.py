import socket
import json

HOST = input('Inserisci IP address del receiver: ')
PORT = input('Inserisci porta del receiver')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.settimeout(5)
    condition = True

    count = 0
    max_test = 10
    config_message_to_server = {
        "KEMid": 0x0010,
        "KDFid": 0x0001,
        "AEADid": 0x0003,
        "PK": '123456789'
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

    receiver_pk = s.recv(1024).decode()
    print(receiver_pk)
    s.settimeout(60)

    send = True

    while True:
        if send:
            message_out = input('Scrivi messaggio | chiudi connessione | attendi: ')
        else:
            print('Aspetto un messaggio')
            in_message = s.recv(2048)
            print('Ho ricevuto il messaggio: ' + in_message.decode())
            if in_message.decode() == 'WAIT':
                message_out = ''
                send = True
            elif in_message.decode() == 'CLOSE':
                s.close()
                print('Chiudo la connessione')
                break

        if message_out == 'q':
            print('Chiudo la connessione')
            s.sendall('CLOSE'.encode())
            s.close()
            break
        elif message_out == 'd':
            print('Mi metto in attesa')
            s.sendall('WAIT'.encode())
            send = False
        elif send:
            print('Invio messaggio')
            s.sendall(message_out.encode())

