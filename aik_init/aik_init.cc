#include "aik_init.h"
#include "../include/global.h"


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <trousers/trousers.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

void openssl_print_errors()
{
    ERR_load_ERR_strings();
    ERR_load_crypto_strings();
    ERR_print_errors_fp(stderr);
}

RSA* openssl_read_key(char *filename)
{
        BIO *b = NULL;
        RSA *rsa = NULL;

        b = BIO_new_file(filename, "r");
        if (b == NULL) {
                fprintf(stderr, "Error opening file for read: %s\n", filename);
                return NULL;
        }

        if ((rsa = PEM_read_bio_RSA_PUBKEY(b, NULL, 0, NULL)) == NULL) {
                fprintf(stderr, "Reading key %s from disk failed.\n", filename);
                openssl_print_errors();
        }
        BIO_free(b);

        return rsa;
}

TSS_FLAG get_tss_key_size(UINT32 size)
{
    if(size <= 512){
        return TSS_KEY_SIZE_512;
    }else if(size <= 1024){
        return TSS_KEY_SIZE_1024;
    }else if(size <= 2048){
        return TSS_KEY_SIZE_2048;
    }else if(size <= 4096){
        return TSS_KEY_SIZE_4096;
    }else if(size <= 8192){
        return TSS_KEY_SIZE_8192;
    }else if(size <= 16384){
        return TSS_KEY_SIZE_16384;
    }

    return TSS_KEY_SIZE_2048;
}

int aik_init_create_aik(TSS_HCONTEXT &hContext, TSS_HTPM &hTpm)
{
    
    TSS_HKEY        hAIK, hSRK, hCAKey;
    TSS_HPOLICY     hAIKPolicy, hSRKPolicy;
    TSS_FLAG        initFlag = TSS_KEY_TYPE_IDENTITY | 
                                TSS_KEY_SIZE_2048 |
                                TSS_KEY_VOLATILE |
                                TSS_KEY_AUTHORIZATION |
                                TSS_KEY_NOT_MIGRATABLE;
    BYTE            wellKnow[] = TSS_WELL_KNOWN_SECRET;
    BYTE            n[2048];
    BYTE           *identityReqBlob, aikLabel[] = "AIK Label";
    UINT32          caKeySize, sizeN, identityReqBlobLen, aikLabelLen = strlen((const char*)aikLabel) + 1;
    RSA*             ca_rsa;

    int result;

    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, TSS_UUID_SRK, &hSRK);
    if (result != TSS_SUCCESS)
    {
        LogBug("Load SRK", result);
        return result;
    }

    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
    if (result != TSS_SUCCESS)
    {
        LogBug("Get SRK policy", result);
        return result;
    }

    result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_SHA1, sizeof(wellKnow), wellKnow);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set SRK secret", result);
        return result;
    }

    //Create a pub key of RSA pair.
    ca_rsa = openssl_read_key((char*)PRIVACY_CA_PUB_KEY_PATH);
    if ((caKeySize = get_tss_key_size(RSA_size(ca_rsa) * 8)) == 0)
    {
        LogError("Bad RSA Key");
        return TSS_E_BAD_PARAMETER;
    }

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TYPE_LEGACY | caKeySize, &hCAKey);
    if (result != TSS_SUCCESS)
    {
        LogBug("Create CA key object", result);
        return result;
    }

    if ((sizeN = BN_bn2bin(ca_rsa->n, n)) <= 0)
    {
        LogError("BN_bn2bin failed");
        ERR_print_errors_fp(stdout);
        Tspi_Context_CloseObject(hContext, hCAKey);
        return TSS_E_FAIL;
    }

    result = Tspi_SetAttribData(hCAKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, sizeN, n);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set hCakey data", result);
        return result;
    }

    result = Tspi_SetAttribUint32(hCAKey, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_ALGORITHM, TSS_ALG_RSA);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set hCakey algorithm", result);
        return result;
    }

    result = Tspi_SetAttribUint32(hCAKey, TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_PRIMES, 2);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set hCakey sushu num", result);
        return result;
    }

    result = Tspi_SetAttribUint32(hCAKey, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_ENCSCHEME, TSS_ES_RSAESPKCSV15);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set hCakey encsheme", result);
        return result;
    }

    //Create AIK object.
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlag, &hAIK);
    if (result != TSS_SUCCESS)
    {
        LogBug("Create AIK object", result);
        return result;
    }

    result = Tspi_TPM_CollateIdentityRequest(hTpm, hSRK, hCAKey, aikLabelLen, aikLabel,
                                        hAIK, TSS_ALG_3DES, &identityReqBlobLen, &identityReqBlob);
    if (result != TSS_SUCCESS)
    {
        LogBug("Collect Identity Request", result);
        return result;
    }

    FILE* fp = fopen(REQUIRE_FILE_PATH, "r");
    fwrite(identityReqBlob, sizeof(BYTE), identityReqBlobLen, fp);
    fclose(fp);

    return result;
}