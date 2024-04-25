#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <my_test_ta.h>
#include "include/client.h"

int main(void)
{
    if (open_connection())
    {
        receive_frame();
    }

    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_MY_TEST_UUID;
    uint32_t err_origin;
    uint8_t public_key[512];
    size_t public_key_size = sizeof(public_key);

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    /*
     * Open a session to the "hello world" TA, the TA will print "hello
     * world!" in the log when the session is created.
     */
    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
             res, err_origin);

    /*
     * Execute a function in the TA by invoking it, in this case
     * we're incrementing a number.
     *
     * The value of command ID part and how the parameters are
     * interpreted is part of the interface provided by the TA.
     */

    /* Clear the TEEC_Operation struct */
    memset(&op, 0, sizeof(op));

    // pass the public key
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = public_key;
    op.params[0].tmpref.size = public_key_size;

    // call TA for public key
    res = TEEC_InvokeCommand(&sess, TA_MY_TEST_CMD_GET_PUBLIC_KEY, &op, &err_origin);
    printf("Actual size of the received public key: %zu\n", public_key_size);
    if (res != TEEC_SUCCESS)
    {
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
    }
    else
    {
        // print the public key
        public_key_size = op.params[0].tmpref.size; // real size of the PK
        printf("Received public key: \n");
        for (size_t i = 0; i < public_key_size; i++)
        {
            printf("%02X", public_key[i]);
            if ((i + 1) % 16 == 0)
                printf("\n");
            else
                printf(" ");
        }
        printf("\n");
    }

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);

    return 0;
}
