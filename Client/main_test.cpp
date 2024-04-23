#include <stdio.h>
#include <string.h>
#include "client.h"

extern char *received_data;

int main()
{
    if (open_connection())
    {
        receive_frame();
    }
    return 0;
}