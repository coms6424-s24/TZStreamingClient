#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#define PAYLOAD_SIZE sizeof(long)

int client_socket;
// Server
int server_port = 9999;
char *server_addr = "34.170.164.154";
char *received_data;

void open_connection()
{
    // Create a socket client
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(server_port);
    inet_pton(AF_INET, server_addr, &(server_address.sin_addr));

    connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address));

    received_data = malloc(4096);
    memset(received_data, 0, 4096);
}

void reveive_frame()
{
    // Receive and assemble the data until the payload size is reached
    while (strlen(received_data) < PAYLOAD_SIZE)
    {
        char buffer[4096];
        recv(client_socket, buffer, 4096, 0);
        strcat(received_data, buffer);
    }

    // Extract the packed message size
    char packed_msg_size[PAYLOAD_SIZE];
    strncpy(packed_msg_size, received_data, PAYLOAD_SIZE);
    memmove(received_data, received_data + PAYLOAD_SIZE, strlen(received_data));
    long msg_size = atol(packed_msg_size);

    // Receive and assemble the frame data until the complete frame is received
    while (strlen(received_data) < msg_size)
    {
        char buffer[4096];
        recv(client_socket, buffer, 4096, 0);
        strcat(received_data, buffer);
    }

    // Extract the frame data
    char frame_data_encrypted[msg_size];
    strncpy(frame_data_encrypted, received_data, msg_size);
    memmove(received_data, received_data + msg_size, strlen(received_data));
}