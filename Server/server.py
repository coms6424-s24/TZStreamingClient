import cv2
import socket
import pickle
import struct
import key
import threading


# Video file
frame_rate = 1  # fps
video_file = "big_buck_bunny_240p_30mb.mp4"


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
        # add client socket to the list
        client_socket, client_address = self.server_socket.accept()
        print(f"[*] Accepted connection from {client_address}")
        if client_address[1] == 9998:  # TA port is 9998
            pass
        else:  # RA port is random
            self.client_socket_list.append((client_socket, client_address[0]))

    def key_exchange(self):  # thread2
        received_data = b""
        while 1:
            received_data, client_address = self.server_socket.recvfrom(4096)
            if client_address[1] == 9998:  # TA port
                public_key = pickle.loads(received_data)
                # send server public key to TA
                self.server_socket.sendto(
                    pickle.dumps(self.server_key.PublicKey()), client_address
                )
                # compute shared key
                self.server_key.compute_shared_key(client_address[0], public_key)

    def stream_video(self, video_file, frame_rate):  # thread3
        # Initialize video capture from the mp4 file
        video_capture = cv2.VideoCapture(video_file)

        while True:
            ret, frame = video_capture.read()
            serialized_frame = pickle.dumps(frame)

            for client_socket, client_address in self.client_socket_list:
                # send frame to client
                message_size = struct.pack("L", len(serialized_frame))
                client_socket.sendall(message_size + serialized_frame)
                # if self.server_key.has_shared_key(client_address):
                #     encrypted_frame = self.server_key.encrypt(
                #         client_address, serialized_frame
                #     )
                #     message_size = struct.pack("L", len(encrypted_frame))
                #     client_socket.sendall(message_size + encrypted_frame)

            cv2.imshow("Server Video", frame)
            cv2.waitKey(int(1000 / frame_rate))
            # Press 'q' to quit
            if cv2.waitKey(1) & 0xFF == ord("q"):
                break

        # Release resources
        video_capture.release()
        cv2.destroyAllWindows()
        self.server_socket.close()

    def __del__(self):
        self.server_socket.close()


my_server = Server()
# launch threads
thread1 = threading.Thread(target=my_server.accept_client)
thread2 = threading.Thread(target=my_server.key_exchange)
thread3 = threading.Thread(target=my_server.stream_video, args=(video_file, frame_rate))
thread1.start()
thread2.start()
thread3.start()
