#include <stdio.h>
#include <string.h>
#include "client.h"

extern char *received_data;

int main()
{
    if (open_connection())
    {
        while (1)
        {
            int msg_size = receive_frame();
            printf("Received %d bytes of data\n", msg_size);
        }
    }
}