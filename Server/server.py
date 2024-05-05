import cv2
import socket
import key
import threading
import pickle


# Video file
frame_rate = 1  # fps
video_file = "big_buck_bunny_240p_30mb.mp4"


class rsa_pub_key:
    def __init__(self):
        self.valid = False

    def is_valid():
        return self.valid

    def set_key(self, e, n):
        self.e = e
        self.n = n
        self.valid = True

    def get_key(self):
        return self.e, self.n

    def encrypt(self, data):
        return pow(data, self.e, self.n)


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
        print("Server running")

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

    def key_exchange(self, client_address, client_socket):  # thread2
        print("wait for public key...")
        received_data = b""
        received_data = client_socket.recv(4096)
        print("received data: ", received_data)
        print("received data length: ", len(received_data))
        # get length
        len_e = int.from_bytes(received_data[0:4], "little")
        len_n = int.from_bytes(received_data[4:8], "little")
        # get e and n
        e = received_data[8 : 8 + len_e]
        n = int.from_bytes(received_data[8 + len_e : 8 + len_e + len_n], "little")
        # print
        print("len_e: ", len_e)
        for i in e:
            print(hex(i), end=":")
        print()
        print("len_n: ", len_n)
        print("n: ", n)
        # load into client record
        for client_socket_t, address, rsa_key in self.client_socket_list:
            if address == client_address[0]:
                rsa_key.set_key(e, n)
                break

    def stream_video(self, video_file, frame_rate):  # thread3
        video_capture = cv2.VideoCapture(video_file)
        while True:
            ret, frame = video_capture.read()
            # serialize the frame
            serialized_frame = cv2.imencode(".jpg", frame)[1].tobytes()
            print(len(serialized_frame), "bytes of data")
            for client_socket, client_address, rsa_key in self.client_socket_list:
                if rsa_key.is_valid():
                    client_socket.sendall(serialized_frame)

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
# thread3 = threading.Thread(target=my_server.stream_video, args=(video_file, frame_rate))
thread1.start()
# thread3.start()
