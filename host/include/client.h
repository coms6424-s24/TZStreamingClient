#ifndef CLIENT
#define CLIENT

int open_connection();
int receive_frame();
void send_pub_key(void *modulus, int mod_len, void *exponent, int exp_len);
extern char *buffer;

#endif