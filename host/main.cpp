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
#define RSA_MAX_PLAIN_LEN_1024 (RSA_KEY_SIZE / 8) - 42
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

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

void prepare_op_out_out(TEEC_Operation *op, char *out1, size_t out1_sz, char *out2, size_t out2_sz)
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

void rsa_get_pub_key(struct tee_attrs *ta)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    char exp[RSA_KEY_SIZE];
    char mod[RSA_KEY_SIZE];

    prepare_op_out_out(&op, exp, RSA_KEY_SIZE, mod, RSA_KEY_SIZE);

    res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_GET_PUB_KEY, &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GET_PUB_KEY) failed 0x%x origin 0x%x\n",
             res, origin);
    printf("\nPublic key: \nExponent: %s\nModulus: %s\n", exp, mod);
}

int main(int argc, char *argv[])
{
    struct tee_attrs ta;
    char clear[RSA_MAX_PLAIN_LEN_1024];
    char ciph[RSA_CIPHER_LEN_1024];

    init_tee_session(&ta);
    printf("\nType something to be encrypted and decrypted in the TA:\n");
    fflush(stdin);
    fgets(clear, sizeof(clear), stdin);

    rsa_gen_keys(&ta);
    rsa_get_pub_key(&ta);
    rsa_encrypt(&ta, clear, RSA_MAX_PLAIN_LEN_1024, ciph, RSA_CIPHER_LEN_1024);
    rsa_decrypt(&ta, ciph, RSA_CIPHER_LEN_1024, clear, RSA_MAX_PLAIN_LEN_1024);

    terminate_tee_session(&ta);
    return 0;
}
