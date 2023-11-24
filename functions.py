def sendMessage(sk, sending):
    while True:
        message = input()
        
        if message.upper() == 'q'.upper():
            print('Chiudo la connessione')
            sk.sendall(sending.seal('CLOSING'.encode()))
            break
        else:
            print("CIFRO E INVIO...")
            sk.sendall(sending.seal(message.encode()))


def getMessage(sk, receiving, sending):
    while True:
        in_message = sk.recv(2048)
        print("DECIFRO...")
        in_message = receiving.open(in_message).decode()
        if in_message == 'CLOSING':
            sk.sendall(sending.seal('CLOSING'.encode()))
            print('CONNESSIONE CHIUSA (PREMI Q)')
            break
        else:
            print('IN: ' + in_message)
