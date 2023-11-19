import socket

# HOST = "::1"  # Standard loopback interface address (localhost)
PORT = 80  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    HOST = socket.gethostbyname(socket.gethostname())
    print('IP address: ' + HOST)
    print('Porta: ' + PORT)
    s.settimeout(60)
    s.bind((HOST, PORT))
    s.listen()

    my_pk = '987654321'

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
        print(config_pk_sender)

        # Mi configuro

        conn.sendall(my_pk.encode())

        s.settimeout(60)

        send = False
        message_out = ''

        while True:
            if send:
                message_out = input('Scrivi messaggio | chiudi connessione | attendi: ')
            else:
                print('Aspetto un messaggio')
                in_message = conn.recv(2048)
                print('Ho ricevuto il messaggio: ' + in_message.decode())
                if in_message.decode() == 'WAIT':
                    message_out = ''
                    send = True
                elif in_message.decode() == 'CLOSE':
                    conn.close()
                    s.close()
                    print('Chiudo la connessione')
                    break

            if message_out == 'q':
                print('Chiudo la connessione')
                conn.sendall('CLOSE'.encode())
                conn.close()
                s.close()
                break
            elif message_out == 'd':
                print('Mi metto in attesa')
                conn.sendall('WAIT'.encode())
                send = False
            elif send:
                print('Invio messaggio')
                conn.sendall(message_out.encode())

