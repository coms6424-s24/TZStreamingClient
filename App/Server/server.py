import cv2
import socket
import pickle
import struct
from Crypto.Cipher import AES

# Video file
frame_rate = 15  # fps
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
        print("Server running")

    def key_generation():
        key = b"Sixteen byte key"
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

    def accept_client(self):
        # add client socket to the list
        client_socket, client_address = self.server_socket.accept()
        print(f"[*] Accepted connection from {client_address}")
        self.client_socket_list.append((client_socket, client_address))

    def stream_video(self, video_file, frame_rate):
        # Initialize video capture from the mp4 file
        video_capture = cv2.VideoCapture(video_file)

        while True:
            # Read a frame from the camera
            ret, frame = video_capture.read()

            # Serialize the frame to bytes
            serialized_frame = pickle.dumps(frame)

            # Pack the data size and frame data
            message_size = struct.pack("L", len(serialized_frame))
            for client_socket, client_address in self.client_socket_list:
                client_socket.sendall(message_size + serialized_frame)

            # Display the frame on the server-side
            cv2.imshow("Server Video", frame)
            # keep framerate
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
my_server.accept_client()
my_server.stream_video(video_file, frame_rate)
