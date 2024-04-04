import cv2
import socket
import pickle
import struct

# Server
server_port = 9999

# Video file
frame_rate = 15 # fps
video_file = "big_buck_bunny_240p_30mb.mp4"

# ------------
server_socket = None

def server_init():
    # Create a socket server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', server_port))  # Replace with the server's IP address
    server_socket.listen(10)
    print("Server running")

def accept_client():
    # Accept a client connection
    client_socket, client_address = server_socket.accept()
    print(f"[*] Accepted connection from {client_address}")
    return client_socket

def send_frames(client_socket, video_file, frame_rate):
    # Initialize video capture from the mp4 file
    video_capture = cv2.VideoCapture(video_file)

    while True:
        # Read a frame from the camera
        ret, frame = video_capture.read()

        # Serialize the frame to bytes
        serialized_frame = pickle.dumps(frame)

        # Pack the data size and frame data
        message_size = struct.pack("L", len(serialized_frame))
        client_socket.sendall(message_size + serialized_frame)

        # Display the frame on the server-side
        # cv2.imshow('Server Video', frame)

        # Press 'q' to quit
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

        # wait for 100ms
        cv2.waitKey(1/frame_rate)

    # Release resources
    video_capture.release()
    cv2.destroyAllWindows()
    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    server_init()
    client_socket = accept_client() # TODO: Multiple clients 
    send_frames(client_socket, video_file, frame_rate)
