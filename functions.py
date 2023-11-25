def sendMessage(socket, sending, aad):
    while True:
        message = input("OUT: ")
        
        if message.upper() == 'q'.upper():
            print('Chiudo la connessione')
            socket.sendall(sending.seal('CLOSING'.encode(), aad))
            break
        else:
            print("CIFRO E INVIO...")
            socket.sendall(sending.seal(message.encode(), aad))


def getMessage(socket, receiving, sending, my_aad, other_aad):
    while True:
        in_message = socket.recv(2048)
        in_message = receiving.open(in_message, other_aad).decode()
        if in_message == 'CLOSING':
            socket.sendall(sending.seal('OK_CLOSING'.encode(), my_aad))
            print('CONNESSIONE CHIUSA (PREMI Q)')
            break
        elif in_message == 'OK_CLOSING':
            break
        else:
            print("DECIFRO...")
            print('IN: ' + in_message)