#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <opencv2>
#define PAYLOAD_SIZE 8
#define BUFFER_SIZE 1 << 30
#define MSG_LEN 230564
using namespace std;

// Server

int server_port = 9999;
string server_addr = "127.0.0.1";
int client_socket;
char *received_data;
char *buffer;

int open_connection()
{
    // Create a socket client
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(server_port);
    inet_pton(AF_INET, server_addr.c_str(), &(server_address.sin_addr));
    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) != -1)
    {
        printf("Connected to the server\n");
        received_data = new char[MSG_LEN];
        memset(received_data, 0, sizeof(received_data));
        buffer = new char[BUFFER_SIZE];
        memset(buffer, 0, sizeof(buffer));
        return 1;
    }
    else
    {
        printf("Failed to connect to the server\n");
        return 0;
    }
}

int receive_frame()
{
    int count;
    while ((count = recv(client_socket, buffer, BUFFER_SIZE, 0)) == 0)
        ;
    strcat(received_data, buffer);
    cv::Mat imgbuf = cv::Mat(480, 640, CV_8U, imageBuf);
    return count;
}