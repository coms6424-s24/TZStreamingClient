import cv2
import socket
import pickle
import struct


class Client:
    def __init__(self) -> None:
        # Server
        self.server_port = 9999
        self.server_addr = "127.0.0.1"
        # Create a socket client
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.server_addr, self.server_port))

    def __del__(self):
        self.client_socket.close()

    def receive_video(self):
        received_data = b""
        payload_size = struct.calcsize("L")  # unsigned long integer

        while True:
            # Receive and assemble the data until the payload size is reached
            while len(received_data) < payload_size:
                received_data += self.client_socket.recv(4096)

            # Extract the packed message size
            packed_msg_size = received_data[:payload_size]
            received_data = received_data[payload_size:]
            msg_size = struct.unpack("L", packed_msg_size)[0]

            # Receive and assemble the frame data until the complete frame is received
            while len(received_data) < msg_size:
                received_data += self.client_socket.recv(4096)

            # Extract the frame data
            frame_data_encrypted = received_data[:msg_size]
            received_data = received_data[msg_size:]

            # TODO: decrypt OP-TEE
            frame_data = frame_data_encrypted

            # Deserialize the received frame
            received_frame = pickle.loads(frame_data)

            # Display the received frame
            cv2.imshow("Client Video", received_frame)

            # Press ‘q’ to quit
            if cv2.waitKey(1) & 0xFF == ord("q"):
                break

        # Release resources
        cv2.destroyAllWindows()


client = Client()
client.receive_video()
