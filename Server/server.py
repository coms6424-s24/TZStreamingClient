# Author: Qiuhong Chen
# Date: 2024-5-4

import cv2
import socket
import key
import threading
import Crypto
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import construct
from Crypto.Cipher import PKCS1_OAEP


# Video file
frame_rate = 1  # fps
video_file = "big_buck_bunny_240p_30mb.mp4"


def print_hex(data):
    for i in data:
        print(hex(i), end=":")
    print("")


class rsa_pub_key:
    def __init__(self):
        self.valid = False

    def is_valid(self):
        return self.valid

    def set_key(self, e, n):
        self.e = e
        self.n = n
        # print("e: ", e)
        # print("n: ", n)
        self.pubkey = construct((n, e))
        self.cipher = PKCS1_OAEP.new(self.pubkey)
        self.valid = True

    def get_key(self):
        return self.e, self.n

    def encrypt(self, data):
        # RSA key size is 1024 bits = 128 bytes
        # devide data into chunks and encrypt each chunk
        encrypted_data = b""
        # chunk size
        input_chunk_size = 32
        output_chunk_size = 128
        # zero padding
        data += b"\x00" * (input_chunk_size - len(data) % input_chunk_size)
        for i in range(0, len(data), input_chunk_size):
            chunk = data[i : i + input_chunk_size]
            # print chunk in hex
            # print_hex(chunk)
            # print("chunk length: ", len(chunk))
            encrypted_chunk = self.cipher.encrypt(chunk)
            # print("encrypted chunk length: ", len(encrypted_chunk))
            # print encrypted_chunk in hex
            # print_hex(encrypted_chunk)
            encrypted_data += encrypted_chunk
        return encrypted_data


class Server:

    def __init__(self) -> None:
        # port
        self.server_port = 9999
        # socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(
            ("", self.server_port)
        )  # Replace with the server's IP address
        self.server_socket.listen(10)
        self.client_socket_list = []
        # key
        self.server_key = key.insecure_key_storage()
        print("Server running...")

    def accept_client(self):  # thread1
        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"[*] Accepted connection from {client_address}")
            self.client_socket_list.append(
                (client_socket, client_address[0], rsa_pub_key())
            )
            # launch a key exchange thread
            thread2 = threading.Thread(
                target=self.key_exchange,
                args=(
                    client_address[0],
                    client_socket,
                ),
            )
            thread2.start()

    def key_exchange(self, client_IP, client_socket):  # thread2

        received_data = b""
        received_data = client_socket.recv(4096)
        # get length
        len_n = int.from_bytes(received_data[0:4], "little")
        len_e = int.from_bytes(received_data[4:8], "little")
        # get n and e
        n = int.from_bytes(
            received_data[8 : 8 + len_n], "little"
        )  # received_data[8 : 8 + len_e]
        e = int.from_bytes(received_data[8 + len_n : 8 + len_e + len_n], "little")
        # print
        print("len_e: ", len_e)
        print("e: ", e)
        print("len_n: ", len_n)
        print("n: ", n)
        # load into client record
        for client_socket_t, address, rsa_key in self.client_socket_list:
            if address == client_IP:
                rsa_key.set_key(e, n)
                print("Public key set for ", client_IP)
                break

    def stream_video(self, video_file, frame_rate):  # thread3
        video_capture = cv2.VideoCapture(video_file)
        while True:
            ret, frame = video_capture.read()
            # serialize the frame
            serialized_frame = cv2.imencode(".jpg", frame)[1].tobytes()
            serialized_frame = ("0123456789").encode()
            print_hex(serialized_frame)
            for client_socket, client_address, rsa_key in self.client_socket_list:
                if rsa_key.is_valid():
                    # encode using rsa public key
                    encrypted_frame = rsa_key.encrypt(serialized_frame)
                    print(len(encrypted_frame), "bytes of encrypted data")
                    # print encrypted_frame in hex
                    print_hex(encrypted_frame)
                    try:
                        client_socket.sendall(encrypted_frame)
                    except:
                        print(f"Error sending frame to {client_address}")
                        self.client_socket_list.remove(
                            (client_socket, client_address, rsa_key)
                        )
                        print(f"Connection with {client_address} closed")
                        client_socket.close()

            cv2.imshow("Server Video", frame)
            cv2.waitKey(int(1000 / frame_rate))

        video_capture.release()
        cv2.destroyAllWindows()
        self.server_socket.close()

    def __del__(self):
        self.server_socket.close()


my_server = Server()
# launch threads
thread1 = threading.Thread(target=my_server.accept_client)
thread3 = threading.Thread(target=my_server.stream_video, args=(video_file, frame_rate))
thread1.start()
thread3.start()
