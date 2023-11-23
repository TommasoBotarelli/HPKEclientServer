def sendMessage(sk, sending, conn = None):
    while True:
        message = input()
        
        if message.upper() == 'q'.upper():
            print('Chiudo la connessione')
            sk.sendall(sending.seal('CLOSING'.encode()))
            if conn is not None:
                conn.close()
            sk.close()
            raise Exception('Connessione chiusa')
        else:
            print("CIFRO E INVIO...")
            sk.sendall(sending.seal(message.encode()))


def getMessage(sk, receiving, conn = None):
    while True:
        in_message = sk.recv(2048)
        print("DECIFRO...")
        in_message = receiving.open(in_message).decode()
        if in_message == 'CLOSING':
            print('Chiudo la connessione')
            if conn is not None:
                conn.close()
            sk.close()
            raise Exception('Connessione chiusa')
        else:
            print('IN: ' + in_message)
