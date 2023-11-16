import socket

HOST = "::1"  # The server's hostname or IP address
PORT = 80  # The port used by the server

with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT, 0, 0))
    for i in range(3):
        message = "Messaggio " + str(i)
        s.sendall(message.encode())
        data = s.recv(1024)
        print(f"Received {data!r}")
