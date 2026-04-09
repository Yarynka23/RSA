import socket
import threading
from sympy import randprime
import json
import hashlib

class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.client_keys = {}
        self.n=None
        self.d=None

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # create key pairs
        p1 = randprime(2**512, 2**1024)
        p2 = randprime(2**512, 2**1024)
        n=p1*p2
        phi=(p1-1)*(p2-1)

        e=65537 #спершу я теж через рандпрайм рахувала, але я прочитала що це стандартне число і так швижше працює алгоритм
        d=pow(e, -1, phi)

        self.n=n
        self.d=d

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.username_lookup[c] = username

            # send public key to the client

            public={'e':e, 'n':n}
            json_data = json.dumps(public)
            c.send(json_data.encode())

            # encrypt the secret with the clients public key

            client_public_key = json.loads(c.recv(2048).decode())
            self.client_keys[c] = {'socket': c, 'username': username,'e': client_public_key['e'], 'n': client_public_key['n']}

            self.clients.append(c)
            self.broadcast(f'new person has joined: {username}')

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str, sender: socket = None):
        hashh = hashlib.sha256(str(msg).encode()).hexdigest()
        msg_int = int.from_bytes(msg.encode(), 'big')

        for client in self.clients:
            if client != sender:
                client_e = self.client_keys[client]['e']
                client_n = self.client_keys[client]['n']

                encrypted = pow(msg_int, client_e, client_n)
                packet = {'hash': hashh, 'encrypted_message': encrypted}
                client.send(json.dumps(packet).encode())

    def handle_client(self, c: socket):
        while True:
            msg = c.recv(1024)
            if not msg:
                break

            packet = json.loads(msg.decode())
            encrypted_int = int(packet['encrypted_message'])

            decrypted_int = pow(encrypted_int, self.d, self.n)
            decrypted_str = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode()

            self.broadcast(decrypted_str, sender=c)

if __name__ == "__main__":
    s = Server(9002)
    s.start()
