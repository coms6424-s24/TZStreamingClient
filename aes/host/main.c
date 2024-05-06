/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <aes_ta.h>

#define AES_TEST_BUFFER_SIZE	4096
#define AES_TEST_KEY_SIZE	16
#define AES_BLOCK_SIZE		16

#define DECODE			0
#define ENCODE			1

clock_t start_time, end_time;


/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_AES_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

void prepare_aes(struct test_ctx *ctx, int encode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = TA_AES_ALGO_CTR;
	op.params[1].value.a = TA_AES_SIZE_128BIT;
	op.params[2].value.a = encode ? TA_AES_MODE_ENCODE :
					TA_AES_MODE_DECODE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			res, origin);
}


void set_key(struct test_ctx *ctx)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    static const char key[AES_TEST_KEY_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81
    };

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = (void*)key;
    op.params[0].tmpref.size = AES_TEST_KEY_SIZE;

    res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY, &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x", res, origin);
}


void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
}

void cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
			res, origin);
}

void decrypt_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_MEMREF_TEMP_OUTPUT,
									 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_COMMAND_DECRYPT, &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(DECRYPT) failed 0x%x origin 0x%x",
			 res, origin);
}

void encrypt_and_decrypt_test(struct test_ctx *ctx)
{
	char plaintext[] = "Hello, world!";
	char ciphertext[128];
	char decryptedtext[128];
	size_t text_size = strlen(plaintext) + 1;  // Include null terminator

	// Encrypt
	printf("Encrypting...\n");
	cipher_buffer(ctx, plaintext, ciphertext, text_size);

	// Decrypt
	printf("Decrypting...\n");
	decrypt_buffer(ctx, ciphertext, decryptedtext, text_size);

	// Check the result
	if (memcmp(plaintext, decryptedtext, text_size) == 0)
		printf("Decryption successful, plaintext matches original\n");
	else
		printf("Decryption failed, plaintext does not match\n");
}


int main(void) {
    struct test_ctx ctx;
    char iv[AES_BLOCK_SIZE];
    char *plaintext = "This is a test message for encryption and decryption.";
    char ciphertext[128];  // Ensure size is appropriate
    char decryptedtext[128];
    size_t text_size = strlen(plaintext) + 1; // Include null terminator

    // printf("Prepare session with the TA\n");
    prepare_tee_session(&ctx);

    for (int i = 0; i < 10; i++) {
		printf("Test %d\n", i + 1);

		double encrypt_time, decrypt_time;

		// Encryption
		// printf("Prepare encode operation\n");
		prepare_aes(&ctx, ENCODE);

		// printf("Load key in TA\n");
		set_key(&ctx);

		// printf("Reset ciphering operation in TA (provides the initial vector)\n");
		memset(iv, 0, sizeof(iv)); // Clear IV
		set_iv(&ctx, iv, AES_BLOCK_SIZE);

		start_time = clock();
		// printf("Encode buffer from TA\n");
		cipher_buffer(&ctx, plaintext, ciphertext, text_size);
		end_time = clock();
		encrypt_time = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
		printf("Encryption time: %f seconds\n", encrypt_time);

		// Decryption
		// printf("Prepare decode operation\n");
		prepare_aes(&ctx, DECODE);

		// printf("Load key in TA\n");
		set_key(&ctx);

		// printf("Reset ciphering operation in TA (provides the initial vector)\n");
		memset(iv, 0, sizeof(iv)); // Clear IV
		set_iv(&ctx, iv, AES_BLOCK_SIZE);

		start_time = clock();
		// printf("Decode buffer from TA\n");
		cipher_buffer(&ctx, ciphertext, decryptedtext, text_size);
		end_time = clock();
		decrypt_time = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
		printf("Decryption time: %f seconds\n", decrypt_time);

		// Finalizing the test results for this iteration
		double total_time = encrypt_time + decrypt_time;
		printf("Test %d: Total execution time: %f seconds\n", i + 1, total_time);

		if (memcmp(plaintext, decryptedtext, text_size) == 0)
			printf("Test %d: Success\n", i + 1);
		else
			printf("Test %d: Failure\n", i + 1);
	}

    terminate_tee_session(&ctx);
    return 0;
}