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
#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <aes_ta.h>

#include <string.h>


#define AES128_KEY_BIT_SIZE		128
#define AES128_KEY_BYTE_SIZE		(AES128_KEY_BIT_SIZE / 8)
#define AES256_KEY_BIT_SIZE		256
#define AES256_KEY_BYTE_SIZE		(AES256_KEY_BIT_SIZE / 8)

/*
 * Ciphering context: each opened session relates to a cipehring operation.
 * - configure the AES flavour from a command.
 * - load key from a command (here the key is provided by the REE)
 * - reset init vector (here IV is provided by the REE)
 * - cipher a buffer frame (here input and output buffers are non-secure)
 */
struct aes_cipher {
	uint32_t algo;			/* AES flavour */
	uint32_t mode;			/* Encode or decode */
	uint32_t key_size;		/* AES key size in byte */
	TEE_OperationHandle op_handle;	/* AES ciphering operation */
	TEE_ObjectHandle key_handle;	/* transient object to load the key */
};

// hold session-specific data
struct aes_session {
    uint8_t *ciphertext;
    uint32_t ciphertext_len;
    TEE_ObjectHandle key_handle;
};


// 256 aes key
static const uint8_t hardcoded_aes_key[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};


/*
 * Few routines to convert IDs from TA API into IDs from OP-TEE.
 */
static TEE_Result ta2tee_algo_id(uint32_t param, uint32_t *algo)
{
	switch (param) {
	case TA_AES_ALGO_ECB:
		*algo = TEE_ALG_AES_ECB_NOPAD;
		return TEE_SUCCESS;
	case TA_AES_ALGO_CBC:
		*algo = TEE_ALG_AES_CBC_NOPAD;
		return TEE_SUCCESS;
	case TA_AES_ALGO_CTR:
		*algo = TEE_ALG_AES_CTR;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid algo %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_key_size(uint32_t param, uint32_t *key_size)
{
	switch (param) {
	case AES128_KEY_BYTE_SIZE:
	case AES256_KEY_BYTE_SIZE:
		*key_size = param;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid key size %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_mode_id(uint32_t param, uint32_t *mode)
{
	switch (param) {
	case TA_AES_MODE_ENCODE:
		*mode = TEE_MODE_ENCRYPT;
		return TEE_SUCCESS;
	case TA_AES_MODE_DECODE:
		*mode = TEE_MODE_DECRYPT;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid mode %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

/*
 * Process command TA_AES_CMD_PREPARE. API in aes_ta.h
 *
 * Allocate resources required for the ciphering operation.
 * During ciphering operation, when expect client can:
 * - update the key materials (provided by client)
 * - reset the initial vector (provided by client)
 * - cipher an input buffer into an output buffer (provided by client)
 */
static TEE_Result alloc_resources(void *session, uint32_t param_types,
				  TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;
	TEE_Attribute attr;
	TEE_Result res;
	char *key;

	/* Get ciphering context from session ID */
	DMSG("Session %p: get ciphering resources", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = ta2tee_algo_id(params[0].value.a, &sess->algo);
	if (res != TEE_SUCCESS)
		return res;

	res = ta2tee_key_size(params[1].value.a, &sess->key_size);
	if (res != TEE_SUCCESS)
		return res;

	res = ta2tee_mode_id(params[2].value.a, &sess->mode);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * Ready to allocate the resources which are:
	 * - an operation handle, for an AES ciphering of given configuration
	 * - a transient object that will be use to load the key materials
	 *   into the AES ciphering operation.
	 */

	/* Free potential previous operation */
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);

	/* Allocate operation: AES/CTR, mode and size from params */
	res = TEE_AllocateOperation(&sess->op_handle,
				    sess->algo,
				    sess->mode,
				    sess->key_size * 8);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		sess->op_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/* Free potential previous transient object */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
					  sess->key_size * 8,
					  &sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		sess->key_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/*
	 * When loading a key in the cipher session, set_aes_key()
	 * will reset the operation and load a key. But we cannot
	 * reset and operation that has no key yet (GPD TEE Internal
	 * Core API Specification – Public Release v1.1.1, section
	 * 6.2.5 TEE_ResetOperation). In consequence, we will load a
	 * dummy key in the operation so that operation can be reset
	 * when updating the key.
	 */
	key = TEE_Malloc(sess->key_size, 0);
	if (!key) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, sess->key_size);

	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		goto err;
	}

	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		goto err;
	}

	return res;

err:
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	sess->op_handle = TEE_HANDLE_NULL;

	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	sess->key_handle = TEE_HANDLE_NULL;

	return res;
}

/*
 * Process command TA_AES_CMD_SET_KEY. API in aes_ta.h
 */
static TEE_Result set_aes_key(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;
	TEE_Attribute attr;
	TEE_Result res;
	uint32_t key_sz;
	char *key;

	/* Get ciphering context from session ID */
	DMSG("Session %p: load key material", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	key = params[0].memref.buffer;
	key_sz = params[0].memref.size;

	if (key_sz != sess->key_size) {
		EMSG("Wrong key size %" PRIu32 ", expect %" PRIu32 " bytes",
		     key_sz, sess->key_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * Load the key material into the configured operation
	 * - create a secret key attribute with the key material
	 *   TEE_InitRefAttribute()
	 * - reset transient object and load attribute data
	 *   TEE_ResetTransientObject()
	 *   TEE_PopulateTransientObject()
	 * - load the key (transient object) into the ciphering operation
	 *   TEE_SetOperationKey()
	 *
	 * TEE_SetOperationKey() requires operation to be in "initial state".
	 * We can use TEE_ResetOperation() to reset the operation but this
	 * API cannot be used on operation with key(s) not yet set. Hence,
	 * when allocating the operation handle, we load a dummy key.
	 * Thus, set_key sequence always reset then set key on operation.
	 */

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_sz);

	TEE_ResetTransientObject(sess->key_handle);
	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		return res;
	}

	TEE_ResetOperation(sess->op_handle);
	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		return res;
	}

	return res;
}

/*
 * Process command TA_AES_CMD_SET_IV. API in aes_ta.h
 */
static TEE_Result reset_aes_iv(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;
	uint32_t iv_sz;
	char *iv;

	/* Get ciphering context from session ID */
	DMSG("Session %p: reset initial vector", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	iv = params[0].memref.buffer;
	iv_sz = params[0].memref.size;

	/*
	 * Init cipher operation with the initialization vector.
	 */
	TEE_CipherInit(sess->op_handle, iv, iv_sz);

	return TEE_SUCCESS;
}

/*
 * Process command TA_AES_CMD_CIPHER. API in aes_ta.h
 */
static TEE_Result cipher_buffer(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: cipher buffer", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[1].memref.size < params[0].memref.size) {
		EMSG("Bad sizes: in %d, out %d", params[0].memref.size,
						 params[1].memref.size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (sess->op_handle == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;

	/*
	 * Process ciphering operation on provided buffers
	 */
	return TEE_CipherUpdate(sess->op_handle,
				params[0].memref.buffer, params[0].memref.size,
				params[1].memref.buffer, &params[1].memref.size);
}

static TEE_Result load_hardcoded_aes_key(TEE_ObjectHandle *key_handle, uint32_t key_size) {
    TEE_Result res;
    TEE_Attribute attr;

    // transient object
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size * 8, key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate transient object");
        return res;
    }

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, hardcoded_aes_key, key_size);

    res = TEE_PopulateTransientObject(*key_handle, &attr, 1);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to populate transient object: 0x%08x", res);
        TEE_FreeTransientObject(*key_handle);
        *key_handle = TEE_HANDLE_NULL;
        return res;
    }

    return TEE_SUCCESS;
}


static TEE_Result encrypt_data(TEE_ObjectHandle key_handle, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint32_t *ciphertext_len) {
    TEE_Result res;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;

    // Allocate the operation
    res = TEE_AllocateOperation(&op_handle, TEE_ALG_AES_ECB_NOPAD, TEE_MODE_ENCRYPT, 256);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate operation handle: 0x%08x", res);
        return res;
    }

    // Set the key
    res = TEE_SetOperationKey(op_handle, key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to set key: 0x%08x", res);
        TEE_FreeOperation(op_handle);
        return res;
    }

    // Perform the encryption
    res = TEE_CipherDoFinal(op_handle, (void *)plaintext, plaintext_len, ciphertext, ciphertext_len);
    if (res != TEE_SUCCESS) {
        EMSG("Encryption failed: 0x%08x", res);
    }

    // Free the operation
    TEE_FreeOperation(op_handle);
    return res;
}

static TEE_Result decrypt_data(TEE_ObjectHandle key_handle, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t *plaintext_len) {
    TEE_Result res;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;

    // Allocate the operation for decryption
    res = TEE_AllocateOperation(&op_handle, TEE_ALG_AES_ECB_NOPAD, TEE_MODE_DECRYPT, 256);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate operation handle for decryption: 0x%08x", res);
        return res;
    }

    // Set the key for decryption
    res = TEE_SetOperationKey(op_handle, key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to set key for decryption: 0x%08x", res);
        TEE_FreeOperation(op_handle);
        return res;
    }

    // Perform the decryption
    res = TEE_CipherDoFinal(op_handle, (void *)ciphertext, ciphertext_len, plaintext, plaintext_len);
    if (res != TEE_SUCCESS) {
        EMSG("Decryption failed: 0x%08x", res);
    }

    // Free the operation
    TEE_FreeOperation(op_handle);
    return res;
}


TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

// TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
// 					TEE_Param __unused params[4],
// 					void __unused **session)
// {
// 	struct aes_cipher *sess;

// 	/*
// 	 * Allocate and init ciphering materials for the session.
// 	 * The address of the structure is used as session ID for
// 	 * the client.
// 	 */
// 	sess = TEE_Malloc(sizeof(*sess), 0);
// 	if (!sess)
// 		return TEE_ERROR_OUT_OF_MEMORY;

// 	sess->key_handle = TEE_HANDLE_NULL;
// 	sess->op_handle = TEE_HANDLE_NULL;

// 	*session = (void *)sess;
// 	DMSG("Session %p: newly allocated", *session);

// 	return TEE_SUCCESS;
// }
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **session) {
    struct aes_session *sess = TEE_Malloc(sizeof(struct aes_session), TEE_MALLOC_FILL_ZERO);
    if (!sess)
        return TEE_ERROR_OUT_OF_MEMORY;

    sess->key_handle = TEE_HANDLE_NULL; // Initialize to NULL
    sess->ciphertext = NULL;
    sess->ciphertext_len = 0;

    *session = sess; // Store the pointer to the session structure
    return TEE_SUCCESS;
}


// void TA_CloseSessionEntryPoint(void *session)
// {
// 	struct aes_cipher *sess;

// 	/* Get ciphering context from session ID */
// 	DMSG("Session %p: release session", session);
// 	sess = (struct aes_cipher *)session;

// 	/* Release the session resources */
// 	if (sess->key_handle != TEE_HANDLE_NULL)
// 		TEE_FreeTransientObject(sess->key_handle);
// 	if (sess->op_handle != TEE_HANDLE_NULL)
// 		TEE_FreeOperation(sess->op_handle);
// 	TEE_Free(sess);
// }
void TA_CloseSessionEntryPoint(void *session) {
    struct aes_session *sess = (struct aes_session *)session;
    if (sess) {
        if (sess->key_handle != TEE_HANDLE_NULL)
            TEE_FreeTransientObject(sess->key_handle);
        if (sess->ciphertext != NULL)
            TEE_Free(sess->ciphertext);
        TEE_Free(sess);
    }
}

// TEE_Result TA_InvokeCommandEntryPoint(void *session,
// 					uint32_t cmd,
// 					uint32_t param_types,
// 					TEE_Param params[4])
// {
// 	TEE_Result res;
TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd, uint32_t param_types, TEE_Param params[4]) {
    struct aes_session *sess = (struct aes_session *)session;
    TEE_Result res;
	TEE_Time start_time, end_time;

	switch (cmd) {
	case TA_AES_CMD_PREPARE:
		return alloc_resources(session, param_types, params);
	case TA_AES_CMD_SET_KEY:
		return set_aes_key(session, param_types, params);
	case TA_AES_CMD_SET_IV:
		return reset_aes_iv(session, param_types, params);
	case TA_AES_CMD_CIPHER:
		return cipher_buffer(session, param_types, params);
	case TA_COMMAND_ENCRYPT:
    {
		// TEE_GetSystemTime(&start_time); // Start time
        const char *text_to_encrypt = "Hello, world!";
        uint32_t text_size = strlen(text_to_encrypt) + 1;  // +1 to include the null terminator
        uint8_t ciphertext[128];
        uint32_t ciphertext_len = sizeof(ciphertext);

        // Load the hardcoded key
        TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
        res = load_hardcoded_aes_key(&key_handle, AES256_KEY_BYTE_SIZE);
        if (res != TEE_SUCCESS) {
            return res;
        }

        // Encrypt the text
        res = encrypt_data(key_handle, (uint8_t *)text_to_encrypt, text_size, ciphertext, &ciphertext_len);
        if (res == TEE_SUCCESS) {
            DMSG("Encrypted text successfully");
            // Optionally, send ciphertext back to the normal world or process it further here
        } else {
            EMSG("Failed to encrypt text: 0x%08x", res);
        }

        // Free the key handle
        if (key_handle != TEE_HANDLE_NULL) {
            TEE_FreeTransientObject(key_handle);
        }
		// TEE_GetSystemTime(&end_time); // End time
        // EMSG("Encryption took %u milliseconds.", end_time.millis - start_time.millis);
		// params[3].value.a = start_time.seconds;
		// params[3].value.b = start_time.millis;
		// params[3].value.c = end_time.seconds;
		// params[3].value.d = end_time.millis;
        return res;
    }
	case TA_COMMAND_DECRYPT:
    {
        // Start timing
        // TEE_GetSystemTime(&start_time);

        if (sess->ciphertext == NULL || sess->key_handle == TEE_HANDLE_NULL)
            return TEE_ERROR_BAD_STATE;

        uint8_t plaintext[128]; // Adjust size as necessary
        uint32_t plaintext_len = sizeof(plaintext);
        res = decrypt_data(sess->key_handle, sess->ciphertext, sess->ciphertext_len, plaintext, &plaintext_len);
        
        // End timing
        // TEE_GetSystemTime(&end_time);
        
        if (res == TEE_SUCCESS) {
            // DMSG("Decryption successful. Took %u milliseconds.", end_time.millis - start_time.millis);
			// params[3].value.a = start_time.seconds;
			// params[3].value.b = start_time.millis;
			// params[3].value.c = end_time.seconds;
			// params[3].value.d = end_time.millis;
            DMSG("Decrypted text: %s", plaintext);
        } else {
            EMSG("Decryption failed: 0x%x", res);
        }
        
        return res;
    }


	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
