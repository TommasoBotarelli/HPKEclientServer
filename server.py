import socket

HOST = "::1"  # Standard loopback interface address (localhost)
PORT = 80  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT, 0, 0))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            conn.sendall(b'Connessione stabilita! \n')
            # Funzioni per arrivare a chiave condivisa
            # Parte di scambio messaggi con chiave condivisa e eventualmente chiudere la connessione quando vogliamo
            data = conn.recv(1024)
            print('Ho ricevuto il messaggio: ' + data.decode('utf-8'))
            if not data:
                break
            conn.sendall(b'Hai mandato il messaggio ' + data + b'\n')
