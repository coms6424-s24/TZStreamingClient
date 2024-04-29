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

TEEC_Result res;
uint32_t eo;
TEEC_Context ctx;
TEEC_Session sess;
const TEEC_UUID uuid = TA_MY_TEST_UUID;
TEEC_Operation op;

const size_t key_size = 2048;
void *inbuf;
size_t inbuf_len;

static void teec_err(TEEC_Result res, uint32_t eo, const char *str)
{
    errx(1, "%s: %#" PRIx32 " (error origin %#" PRIx32 ")", str, res, eo);
}

void TEE_get_key()
{
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].value.a = key_size;

    res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_GEN_KEY, &op, &eo);
    if (res)
        teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_GEN_KEY)");
}

void TEE_encrypt()
{
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = inbuf;
    op.params[0].tmpref.size = inbuf_len;

    res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT, &op, &eo);
    if (eo != TEEC_ORIGIN_TRUSTED_APP || res != TEEC_ERROR_SHORT_BUFFER)
        teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_ENCRYPT)");

    op.params[1].tmpref.buffer = malloc(op.params[1].tmpref.size);
    if (!op.params[1].tmpref.buffer)
        err(1, "Cannot allocate out buffer of size %zu",
            op.params[1].tmpref.size);

    res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT, &op, &eo);
    if (res)
        teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_ENCRYPT)");

    printf("Encrypted buffer: ");
    for (size_t n = 0; n < op.params[1].tmpref.size; n++)
        printf("%02x ", ((uint8_t *)op.params[1].tmpref.buffer)[n]);
    printf("\n");
}

int main(void)
{
    // TEE init
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res)
        errx(1, "TEEC_InitializeContext(NULL, x): %#" PRIx32, res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                           NULL, &eo);
    if (res)
        teec_err(res, eo, "TEEC_OpenSession(TEEC_LOGIN_PUBLIC)");

    TEE_get_key();
    inbuf = (void *)"12121212121212121212121212121212121212121212121212121212";
    inbuf_len = strlen((char *)inbuf);
    TEE_encrypt();

    if (open_connection())
    {
        receive_frame();
    }

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);

    return 0;
}
