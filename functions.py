def sendMessage(sk, sending, conn = None):
    while True:
        message = input("Inserisci messaggio: ")
        
        if message.upper() == 'q'.upper():
            print('Chiudo la connessione')
            sk.sendall(sending.seal('CLOSING'.encode()))
            if conn != None:
                conn.close()
            sk.close()
            break
        else:
            print("CIFRO...")
            sk.sendall(sending.seal(message.encode()))
        
        

def getMessage(sk, receiving, conn = None):
    while True:
        in_message = sk.recv(2048)
        print("DECIFRO...")
        in_message = receiving.open(in_message).decode()
        if in_message == 'CLOSING':
            print('Chiudo la connessione')
            if conn != None:
                conn.close()
            sk.close()
            break
        else:
            print('Ho ricevuto il messaggio: ' + in_message)
