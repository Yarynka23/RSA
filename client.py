import socket
import threading
from sympy import randprime
import json
import hashlib

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

        #these variables were added by me
        self.n=None
        self.d=None

        self.server_n=None
        self.server_e=None
    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return None

        self.s.send(self.username.encode())

        # create key pairs
        p1 = randprime(2**512, 2**1024)
        p2 = randprime(2**512, 2**1024)
        n=p1*p2
        phi=(p1-1)*(p2-1)

        e=65537 #спершу я теж через рандпрайм рахувала, але я прочитала що це стандартне число і так швижше працює алгоритм
        d=pow(e, -1, phi)

        self.n=n
        self.d=d
        # exchange public keys
        public={'e':e, 'n':n}
        json_data = json.dumps(public)
        self.s.send(json_data.encode())
        # receive the encrypted secret key
        server_public_key = json.loads(self.s.recv(1024).decode())
        self.server_n=server_public_key['n']
        self.server_e=server_public_key['e']

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        while True:
            message = self.s.recv(2048) # розмір в два рази більший бо приймається і хеш і саме повідомлення, не знаю чи мала я право його змінювати
            if not message:
                break
            packet = json.loads(message.decode())
            hashh = packet['hash']
            msg = packet['encrypted_message']

            decrypted_int = pow(int(msg), self.d, self.n)
            decrypted = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode()
            current_hash = hashlib.sha256(str(decrypted).encode()).hexdigest()

            if current_hash == hashh:
                print(decrypted)
            else:
                print("!!! ПОПЕРЕДЖЕННЯ: Повідомлення було змінено або пошкоджено !!!")

    def write_handler(self):
        while True:
            message = input()
            if not message:
                break
            hashh = hashlib.sha256(str(message).encode()).hexdigest()
            msg = int.from_bytes(message.encode(), 'big')
            encrypted = pow(msg, self.server_e, self.server_n)
            packet = {'hash': hashh,'encrypted_message': encrypted}
            self.s.send(json.dumps(packet).encode())

if __name__ == "__main__":
    name=input('Name: ')
    cl = Client("127.0.0.1", 9000, name)
    cl.init_connection()
