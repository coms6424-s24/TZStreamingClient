// Author: Qiuhong Chen
// Date: 2024-5-4

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include "my_test_ta.h" //#include <my_test_ta.h>
#include "include/client.h"

#define RSA_KEY_SIZE 1024
#define BUFFER_SIZE 1 << 16
#define RSA_MAX_PLAIN_LEN_1024 (RSA_KEY_SIZE / 8) - 42
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

// public key
#define BigIntSizeInU32(n) ((((n) + 31) / 32) + 2)

// decrypted frame
char *decrypted_frame;

class pub_key
{
public:
    uint32_t exponentLen;
    uint32_t *exponent;
    uint32_t modulusLen;
    uint32_t *modulus;

    pub_key()
    {
        exponentLen = BigIntSizeInU32(RSA_KEY_SIZE) * sizeof(uint32_t);
        exponent = new uint32_t[exponentLen];
        modulusLen = BigIntSizeInU32(RSA_KEY_SIZE) * sizeof(uint32_t);
        modulus = new uint32_t[modulusLen];
    }

    ~pub_key()
    {
        delete[] exponent;
        delete[] modulus;
    }
};

struct tee_attrs
{
    TEEC_Context ctx;
    TEEC_Session sess;
};

void init_tee_session(struct tee_attrs *ta)
{
    TEEC_UUID uuid = TA_MY_TEST_UUID;
    uint32_t origin;
    TEEC_Result res;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ta->ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InitializeContext failed with code 0x%x\n", res);

    /* Open a session with the TA */
    res = TEEC_OpenSession(&ta->ctx, &ta->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_Opensession failed with code 0x%x origin 0x%x\n", res, origin);
}

void terminate_tee_session(struct tee_attrs *ta)
{
    TEEC_CloseSession(&ta->sess);
    TEEC_FinalizeContext(&ta->ctx);
}

void prepare_op(TEEC_Operation *op, char *in, size_t in_sz, char *out, size_t out_sz)
{
    memset(op, 0, sizeof(*op));

    op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                      TEEC_MEMREF_TEMP_OUTPUT,
                                      TEEC_NONE, TEEC_NONE);
    op->params[0].tmpref.buffer = in;
    op->params[0].tmpref.size = in_sz;
    op->params[1].tmpref.buffer = out;
    op->params[1].tmpref.size = out_sz;
}

void prepare_op_out_out(TEEC_Operation *op, void *out1, size_t out1_sz, void *out2, size_t out2_sz)
{
    memset(op, 0, sizeof(*op));

    op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                      TEEC_MEMREF_TEMP_OUTPUT,
                                      TEEC_NONE, TEEC_NONE);
    op->params[0].tmpref.buffer = out1;
    op->params[0].tmpref.size = out1_sz;
    op->params[1].tmpref.buffer = out2;
    op->params[1].tmpref.size = out2_sz;
}

void rsa_gen_keys(struct tee_attrs *ta)
{
    TEEC_Result res;

    res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_GENKEYS, NULL, NULL);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
    printf("\n=========== Keys already generated. ==========\n");
}

void rsa_encrypt(struct tee_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    printf("\n============ RSA ENCRYPT CA SIDE ============\n");
    prepare_op(&op, in, in_sz, out, out_sz);

    res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_ENCRYPT,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",
             res, origin);
    printf("\nThe text sent was encrypted: %s\n", out);
}

void rsa_decrypt(struct tee_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    printf("\n============ RSA DECRYPT CA SIDE ============\n");
    prepare_op(&op, in, in_sz, out, out_sz);

    res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_DECRYPT, &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_DECRYPT) failed 0x%x origin 0x%x\n",
             res, origin);
    printf("\nThe text sent was decrypted: %s\n", (char *)op.params[1].tmpref.buffer);
}

void rsa_get_pub_key(struct tee_attrs *ta, pub_key *pk)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    prepare_op_out_out(&op, pk->exponent, pk->exponentLen, pk->modulus, pk->modulusLen);
    res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_GET_PUB_KEY, &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GET_PUB_KEY) failed 0x%x origin 0x%x\n",
             res, origin);
    pk->exponentLen = op.params[0].tmpref.size;
    pk->modulusLen = op.params[1].tmpref.size;
    printf("\n============== Public key ==============\n");
    // print exponent and modulus
    printf("Exponent %d bytes:\n", op.params[0].tmpref.size);
    for (int i = 0; i < pk->exponentLen; i++)
    {
        printf("%02x:", ((char *)pk->exponent)[i]);
    }
    printf("\n");
    printf("Modulus %d bytes:\n", op.params[1].tmpref.size);
    for (int i = 0; i < pk->modulusLen; i++)
    {
        printf("%02x:", ((char *)pk->modulus)[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    struct tee_attrs ta;
    char clear[RSA_MAX_PLAIN_LEN_1024] = "0123456789";
    // print clear in hex
    for (int i = 0; i < RSA_MAX_PLAIN_LEN_1024; i++)
    {
        printf("%02x:", clear[i]);
    }
    printf("\n");
    char ciph[RSA_CIPHER_LEN_1024];

    init_tee_session(&ta);

    // generate key and get public key from TA
    rsa_gen_keys(&ta);
    pub_key pk;
    rsa_get_pub_key(&ta, &pk);
    // test
    rsa_encrypt(&ta, clear, RSA_MAX_PLAIN_LEN_1024, ciph, RSA_CIPHER_LEN_1024);
    rsa_decrypt(&ta, ciph, RSA_CIPHER_LEN_1024, clear, RSA_MAX_PLAIN_LEN_1024);
    // send to server
    if (open_connection())
    {
        decrypted_frame = new char[BUFFER_SIZE];
        send_pub_key(pk.modulus, pk.modulusLen, pk.exponent, pk.exponentLen);
        int cnt = 3;
        while (1)
        {
            int count = receive_frame();
            if (cnt-- > 0)
                continue;
            printf("Received %d bytes\n", count);
            // print received data in hex
            for (int i = 0; i < count; i++)
            {
                printf("%02x:", buffer[i]);
            }
            printf("\n");
            // decrypt
            int input_chunk_size = 128;
            int output_chunk_size = 128;
            printf("chunk number %d", count / input_chunk_size);
            for (int i = 0; i < count / input_chunk_size; i++)
            {
                // print the chunk in hex
                for (int j = 0; j < input_chunk_size; j++)
                {
                    printf("%02x:", buffer[i * input_chunk_size + j]);
                }
                printf("\n");
                rsa_decrypt(&ta, buffer + i * input_chunk_size, RSA_CIPHER_LEN_1024, decrypted_frame + i * output_chunk_size, RSA_MAX_PLAIN_LEN_1024);
            }
            int decrypted_count = count * output_chunk_size / input_chunk_size;
            printf("decrypted %d bytes\n", decrypted_count);
            for (int i = 0; i < decrypted_count; i++)
            {
                // print decrypted frame in char
                printf("%c", decrypted_frame[i]);
            }
            printf("\n");
        }
    }

    terminate_tee_session(&ta);
    return 0;
}
