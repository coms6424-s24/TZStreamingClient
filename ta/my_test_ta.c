/*
 * Copyright (c) 2016, Linaro Limited
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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <my_test_ta.h>

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
// TEE_Result TA_CreateEntryPoint(void)
// {
// 	DMSG("has been called");

// 	return TEE_SUCCESS;
// }

// public key variable
uint8_t g_public_modulus[256];
uint8_t g_public_exponent[3]; 
uint32_t g_public_modulus_size = sizeof(g_public_modulus);
uint32_t g_public_exponent_size = sizeof(g_public_exponent);

TEE_Result TA_CreateEntryPoint(void) {
    TEE_Result res;
    TEE_ObjectHandle rsa_keypair = TEE_HANDLE_NULL;
    uint32_t key_size = 2048;

    // Allocate RSA keypair object
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &rsa_keypair);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate RSA keypair object");
        return res;
    }

    // Generate RSA keypair
    res = TEE_GenerateKey(rsa_keypair, key_size, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to generate RSA keypair");
        TEE_FreeTransientObject(rsa_keypair);
        return res;
    }

    // Get the public key modulus
    res = TEE_GetObjectBufferAttribute(rsa_keypair, TEE_ATTR_RSA_MODULUS, g_public_modulus, &g_public_modulus_size);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to extract RSA public key modulus");
        TEE_FreeTransientObject(rsa_keypair);
        return res;
    }

    // Get the public exponent
    res = TEE_GetObjectBufferAttribute(rsa_keypair, TEE_ATTR_RSA_PUBLIC_EXPONENT, g_public_exponent, &g_public_exponent_size);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to extract RSA public key exponent");
        TEE_FreeTransientObject(rsa_keypair);
        return res;
    }

    IMSG("Public key modulus and exponent extracted and stored.");

    TEE_FreeTransientObject(rsa_keypair);

    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello qc2335!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye qc2335!\n");
}

static TEE_Result inc_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a += 10;
	IMSG("Increase value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a--;
	IMSG("Decrease value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}
// put public key into TEE_Param params and send to host

static TEE_Result get_public_key(uint32_t param_types, TEE_Param params[4])
{
    // Calculate total size of the public key (modulus + exponent)
    uint32_t total_public_key_size = g_public_modulus_size + g_public_exponent_size;

    // Check buffer size
    if (params[0].memref.size < total_public_key_size) {
        params[0].memref.size = total_public_key_size;
        return TEE_ERROR_SHORT_BUFFER;
    }

    // Copy modulus and exponent to the buffer
    TEE_MemMove(params[0].memref.buffer, g_public_modulus, g_public_modulus_size);
    TEE_MemMove((uint8_t *)params[0].memref.buffer + g_public_modulus_size, g_public_exponent, g_public_exponent_size);

    // Update the size to reflect the total size of the public key
    params[0].memref.size = total_public_key_size;

    return TEE_SUCCESS;
}


/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_MY_TEST_CMD_INC_VALUE:
		return inc_value(param_types, params);
	case TA_MY_TEST_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_MY_TEST_CMD_GET_PUBLIC_KEY:
    	return get_public_key(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
