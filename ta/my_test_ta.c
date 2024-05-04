#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <my_test_ta.h>
#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

struct rsa_session
{
    TEE_OperationHandle op_handle; /* RSA operation */
    TEE_ObjectHandle key_handle;   /* Key handle */
};

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key)
{
    TEE_Result ret = TEE_SUCCESS;
    TEE_ObjectInfo key_info;
    ret = TEE_GetObjectInfo1(key, &key_info);
    if (ret != TEE_SUCCESS)
    {
        EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);
        return ret;
    }

    ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
    if (ret != TEE_SUCCESS)
    {
        EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
        return ret;
    }
    DMSG("\n========== Operation allocated successfully. ==========\n");

    ret = TEE_SetOperationKey(*handle, key);
    if (ret != TEE_SUCCESS)
    {
        EMSG("\nFailed to set key : 0x%x\n", ret);
        return ret;
    }
    DMSG("\n========== Operation key already set. ==========\n");

    return ret;
}

TEE_Result check_params(uint32_t param_types)
{
    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    /* Safely get the invocation parameters */
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
    return TEE_SUCCESS;
}

TEE_Result RSA_create_key_pair(void *session)
{
    TEE_Result ret;
    size_t key_size = RSA_KEY_SIZE;
    struct rsa_session *sess = (struct rsa_session *)session;

    ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
    if (ret != TEE_SUCCESS)
    {
        EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
        return ret;
    }
    DMSG("\n========== Transient object allocated. ==========\n");

    ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
    if (ret != TEE_SUCCESS)
    {
        EMSG("\nGenerate key failure: 0x%x\n", ret);
        return ret;
    }
    DMSG("\n========== Keys generated. ==========\n");
    return ret;
}

TEE_Result Get_Pub_key(void *session, uint32_t param_types, TEE_Param params[4])
{
    DMSG("\n========== test1. ==========\n");
    struct rsa_session *sess = (struct rsa_session *)session;

    TEE_BigInt *out_param_exponent = (TEE_BigInt *)params[0].memref.buffer;
    TEE_BigInt *out_param_modulus = (TEE_BigInt *)params[1].memref.buffer;
    size_t key_size = RSA_KEY_SIZE;
    size_t bigInt_len;
    TEE_BigInt *bigIntExp;
    TEE_BigInt *bigIntMod;
    uint8_t buffer[RSA_KEY_SIZE] = {0};
    uint8_t mod[RSA_KEY_SIZE] = {0};
    uint32_t bufferlen;
    uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
    TEE_ObjectInfo info;
    uint32_t modlen;
    uint32_t res;
    TEE_OperationHandle handle = (TEE_OperationHandle)NULL;

    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                               TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
    DMSG("\n========== test2. ==========\n");
    /* initialize the BigInt structure */
    bigInt_len = TEE_BigIntSizeInU32(key_size);
    DMSG("\n========== test2.1 ==========\n");
    bigIntExp = (TEE_BigInt *)TEE_Malloc(bigInt_len * sizeof(TEE_BigInt), TEE_MALLOC_FILL_ZERO);
    DMSG("\n========== test2.2 ==========\n");
    TEE_BigIntInit(bigIntExp, key_size);
    DMSG("\n========== test2.3 ==========\n");
    bigIntMod = (TEE_BigInt *)TEE_Malloc(bigInt_len * sizeof(TEE_BigInt), TEE_MALLOC_FILL_ZERO);
    DMSG("\n========== test2.4 ==========\n");
    TEE_BigIntInit(bigIntMod, key_size);
    DMSG("\n========== test3. ==========\n");
    /* get the public value, as an octet string */
    bufferlen = sizeof(buffer);
    res = TEE_GetObjectBufferAttribute(sess->key_handle, TEE_ATTR_RSA_PUBLIC_EXPONENT, buffer, &bufferlen);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_GetObjectBufferAttribute failed!TEE_GetObjectBufferAttribute res: 0x%x", res);
    }
    modlen = sizeof(mod);
    res = TEE_GetObjectBufferAttribute(sess->key_handle, TEE_ATTR_RSA_MODULUS, mod, &modlen);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_GetObjectBufferAttribute (Modulus) failed!TEE_GetObjectBufferAttribute res: 0x%x", res);
    }

    /* convert the octet string to a BigInt */
    res = TEE_BigIntConvertFromOctetString(bigIntExp, buffer, bufferlen, 0);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_BigIntConvertFromOctetString failed!TEE_BigIntConvertFromOctetString res: 0x%x", res);
    }

    res = TEE_BigIntConvertFromOctetString(bigIntMod, mod, modlen, 0);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_BigIntConvertFromOctetString failed!TEE_BigIntConvertFromOctetString res: 0x%x", res);
    }
    DMSG("\n========== test4. ==========\n");
    memcpy(out_param_exponent, bigIntExp, (bigInt_len * sizeof(TEE_BigInt)));
    memcpy(out_param_modulus, bigIntMod, (bigInt_len * sizeof(TEE_BigInt)));

    TEE_Free(bigIntExp);
    TEE_Free(bigIntMod);
    DMSG("\n========== test5. ==========\n");
    return TEE_SUCCESS;
}

TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
    struct rsa_session *sess = (struct rsa_session *)session;

    if (check_params(param_types) != TEE_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;

    void *plain_txt = params[0].memref.buffer;
    size_t plain_len = params[0].memref.size;
    void *cipher = params[1].memref.buffer;
    size_t cipher_len = params[1].memref.size;

    DMSG("\n========== Preparing encryption operation ==========\n");
    ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
    if (ret != TEE_SUCCESS)
    {
        EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
        goto err;
    }

    DMSG("\nData to encrypt: %s\n", (char *)plain_txt);
    ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
                                plain_txt, plain_len, cipher, &cipher_len);
    if (ret != TEE_SUCCESS)
    {
        EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
        goto err;
    }
    DMSG("\nEncrypted data: %s\n", (char *)cipher);
    DMSG("\n========== Encryption successfully ==========\n");
    return ret;

err:
    TEE_FreeOperation(sess->op_handle);
    TEE_FreeOperation(sess->key_handle);
    return ret;
}

TEE_Result RSA_decrypt(void *session, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret;
    uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
    struct rsa_session *sess = (struct rsa_session *)session;

    if (check_params(param_types) != TEE_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;

    void *plain_txt = params[1].memref.buffer;
    size_t plain_len = params[1].memref.size;
    void *cipher = params[0].memref.buffer;
    size_t cipher_len = params[0].memref.size;

    DMSG("\n========== Preparing decryption operation ==========\n");
    ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_DECRYPT, sess->key_handle);
    if (ret != TEE_SUCCESS)
    {
        EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
        goto err;
    }

    DMSG("\nData to decrypt: %s\n", (char *)cipher);
    ret = TEE_AsymmetricDecrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
                                cipher, cipher_len, plain_txt, &plain_len);
    if (ret != TEE_SUCCESS)
    {
        EMSG("\nFailed to decrypt the passed buffer: 0x%x\n", ret);
        goto err;
    }
    DMSG("\nDecrypted data: %s\n", (char *)plain_txt);
    DMSG("\n========== Decryption successfully ==========\n");
    return ret;

err:
    TEE_FreeOperation(sess->op_handle);
    TEE_FreeTransientObject(sess->key_handle);
    return ret;
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

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
                                    TEE_Param __unused params[4],
                                    void __unused **session)
{
    struct rsa_session *sess;
    sess = TEE_Malloc(sizeof(*sess), 0);
    if (!sess)
        return TEE_ERROR_OUT_OF_MEMORY;

    sess->key_handle = TEE_HANDLE_NULL;
    sess->op_handle = TEE_HANDLE_NULL;

    *session = (void *)sess;
    DMSG("\nSession %p: newly allocated\n", *session);

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
    struct rsa_session *sess;

    /* Get ciphering context from session ID */
    DMSG("Session %p: release session", session);
    sess = (struct rsa_session *)session;

    /* Release the session resources
       These tests are mandatories to avoid PANIC TA (TEE_HANDLE_NULL) */
    if (sess->key_handle != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(sess->key_handle);
    if (sess->op_handle != TEE_HANDLE_NULL)
        TEE_FreeOperation(sess->op_handle);
    TEE_Free(sess);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
                                      uint32_t cmd,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    switch (cmd)
    {
    case TA_RSA_CMD_GENKEYS:
        return RSA_create_key_pair(session);
    case TA_RSA_CMD_ENCRYPT:
        return RSA_encrypt(session, param_types, params);
    case TA_RSA_CMD_DECRYPT:
        return RSA_decrypt(session, param_types, params);
    case TA_RSA_CMD_GET_PUB_KEY:
        return Get_Pub_key(session, param_types, params);
    default:
        EMSG("Command ID 0x%x is not supported", cmd);
        return TEE_ERROR_NOT_SUPPORTED;
    }
}