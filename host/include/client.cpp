// Author: Qiuhong Chen
// Date: 2024-5-4

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
// #include <opencv2/core.hpp>
// #include <opencv2/highgui.hpp>
#define PAYLOAD_SIZE 8
#define BUFFER_SIZE 1 << 16
using namespace std;

// Server

int server_port = 9999;
string server_addr = "10.128.0.6";
int client_socket;
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
    // cv::namedWindow("Client", cv::WINDOW_AUTOSIZE);
    // cv::Mat rawData(1, count, CV_8UC1, (void *)buffer);
    // cv::Mat decoded_frame = cv::imdecode(rawData, cv::IMREAD_COLOR);
    // cv::imshow("Client", decoded_frame);
    // cv::waitKey(25);
    int count = recv(client_socket, buffer, BUFFER_SIZE, 0);
    return count;
}

void send_pub_key(void *modulus, int mod_len, void *exponent, int exp_len)
{
    // combine into one message
    char *msg = new char[mod_len + exp_len + 10];
    // endianess unsolved!!!!!
    memcpy(msg, &mod_len, 4);
    memcpy(msg + 4, &exp_len, 4);
    memcpy(msg + 8, modulus, mod_len);
    memcpy(msg + 8 + mod_len, exponent, exp_len);
    if (send(client_socket, msg, mod_len + exp_len + 8, 0) != -1)
    {
        printf("Public key sent to server.\n");
    }
}