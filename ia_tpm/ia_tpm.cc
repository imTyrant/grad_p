#include "ia_tpm.h"
#include "../include/global.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <trousers/trousers.h>

#include <openssl/evp.h>


int ia_tpm_init(TSS_HCONTEXT &hContext, TSS_HTPM &hTpm)
{
    int result;
    //创建TSS上下文对象
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS)
    {
        LogBug("Tspi Context Creation", result);
        return result;
    }
    //链接本地TSS上下文对象
    result = Tspi_Context_Connect(hContext, NULL);
    if (result != TSS_SUCCESS)
    {
        LogBug("Tspi Context Connect", result);
        return result;
    }
    //获取上下文对象
    result = Tspi_Context_GetTpmObject(hContext, &hTpm);
    if (result != TSS_SUCCESS)
    {
        LogBug("Tspi Get Tpm Object", result);
        return result;
    }
    return result;
}

int ia_tpm_close(TSS_HCONTEXT &hContext, TSS_HTPM &hTpm)
{
    int result;

    result = Tspi_Context_Close(hContext);
    if (result != TSS_SUCCESS)
    {
        LogBug("Close global context handle", result);
        return result;
    }
    return result;
}

int ia_tpm_seal_platform_key(TSS_HCONTEXT &hContext, UINT32 PlatformKeySize, BYTE* PlatformKey)
{
    TSS_HPOLICY     hPolicy, hSRKPolicy;
    TSS_HKEY        hKey, hSRK;
    TSS_HENCDATA    hEncData;
    TSS_FLAG        keyFlags = TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 |
	                    TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
	                    TSS_KEY_NOT_MIGRATABLE;

    BYTE            wellKnow[] = TSS_WELL_KNOWN_SECRET;
    UINT32          sealedPKSize;
    BYTE*           sealedPK;
    UINT32          sealKeSize;
    BYTE*           sealKey;

    BIO*            bdata=NULL; 
    BIO*            b64=NULL;
    
    int result;

    //Get SRK object
    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, TSS_UUID_SRK, &hSRK);
    if (result != TSS_SUCCESS)
    {
        LogBug("Get SRK object", result);
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
        LogBug("Set SRK policy", result);
        return result;
    }

    //Create SealKey which will be used to seal PlatformKey.
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, keyFlags, &hKey);
    if (result != TSS_SUCCESS)
    {
        LogBug("Create SealKey object", result);
        return result;
    }

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hPolicy);
    if (result != TSS_SUCCESS)
    {
        LogBug("Create SealKey policy object", result);
        return result;
    }

    result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1, sizeof(wellKnow), wellKnow);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set SealKey secret", result);
        return result;
    }

    result = Tspi_Policy_AssignToObject(hPolicy, hKey);
    if (result != TSS_SUCCESS)
    {
        LogBug("Assign policy to SealKey object", result);
        return result;
    }

    result = Tspi_Key_CreateKey(hKey, hSRK, 0);
    if (result != TSS_SUCCESS)
    {
        LogBug("Create SealKey", result);
        return result;
    }
    
    //Loading SealKey to TPM.
    result = Tspi_Key_LoadKey(hKey, hSRK);
    if (result != TSS_SUCCESS)
    {
        LogBug("Load SealKey", result);
        return result;
    }

    //Creat a EncData object which will contain  
    //the PlatfromKey after it is encrypted by SealKey.
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_SEAL, &hEncData);
    if (result != TSS_SUCCESS)
    {
        LogBug("Create EncData object of Platform", result);
        return result;
    }

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hPolicy);
    if (result != TSS_SUCCESS)
    {
        LogBug("Create EncData policy object", result);
        return result;
    }

    result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1, sizeof(wellKnow), wellKnow);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set EncData secret", result);
        return result;
    }

    result = Tspi_Policy_AssignToObject(hPolicy, hEncData);
    if (result != TSS_SUCCESS)
    {
        LogBug("Assign policy to EncData object", result);
        return result;
    }

    //Seal PlatformKey.
    result = Tspi_Data_Seal(hEncData, hKey, PlatformKeySize, PlatformKey, 0);
    if (result != TSS_SUCCESS)
    {
        LogBug("Seal PlatfromKey", result);
        return result;
    }

    //Get sealed PlatformKey and sealing key.
    result = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, &sealedPKSize, &sealedPK);
    if (result != TSS_SUCCESS)
    {
        LogBug("Get Sealed PlatfromKey", result);
        return result;
    }

    result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, &sealKeSize, &sealKey);
    if (result != TSS_SUCCESS)
    {
        LogBug("Get seal key", result);
        return result;
    }

    //Output data //////////////////////////////////////////////////////////////////
    /* Create a BIO to perform base64 encoding */
	if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
		LogBug("Unable to open base64 BIO", IA_TPM_NOT_TSS_ERROR);
		return IA_TPM_NOT_TSS_ERROR;
	}

	/* Create a BIO for the output file */
	if ((bdata = BIO_new(BIO_s_file())) == NULL) {
		LogBug("Unable to open output BIO", IA_TPM_NOT_TSS_ERROR);
		return IA_TPM_NOT_TSS_ERROR;
	}

	/* Assign the output file to the BIO */
	if (strlen(IA_TPM_PLATFROM_KEY_PATH) == 0)
		BIO_set_fp(bdata, stdout, BIO_NOCLOSE);
	else if (BIO_write_filename(bdata, (void *)IA_TPM_PLATFROM_KEY_PATH) <= 0) {
		LogBug("Unable to open output file ./PlatformKey.enc", IA_TPM_NOT_TSS_ERROR);
		return IA_TPM_NOT_TSS_ERROR;
	}

	/* Output the sealed data header string */
	BIO_puts(bdata, TPMSEAL_HDR_STRING);

	/* Sealing key used on the TPM */
	BIO_puts(bdata, TPMSEAL_TSS_STRING);
	bdata = BIO_push(b64, bdata);
	BIO_write(bdata, sealKey, sealKeSize);
	if (BIO_flush(bdata) != 1) {
		LogBug("Unable to flush output", IA_TPM_NOT_TSS_ERROR);
		return IA_TPM_NOT_TSS_ERROR;
	}
	bdata = BIO_pop(b64);

	/* Sealed PlatformKey */
	BIO_puts(bdata, TPMSEAL_EVP_STRING);
	bdata = BIO_push(b64, bdata);
	BIO_write(bdata, sealedPK, sealedPKSize);
	if (BIO_flush(bdata) != 1) {
		LogBug("Unable to flush output", IA_TPM_NOT_TSS_ERROR);
		return IA_TPM_NOT_TSS_ERROR;
	}
	bdata = BIO_pop(b64);

    BIO_puts( bdata, TPMSEAL_FTR_STRING);

    if (bdata)
		BIO_free(bdata);
	if (b64)
		BIO_free(b64);

    return TSS_SUCCESS;
}

/*
 * Reading PlatformKey from file which is encoded by base64.
 */
int ia_tpm_read_PK_file(BYTE* &sealKey, UINT32 &sealKeySize, BYTE* &sealedPK, UINT32 &sealedPKSize)
{
    int rc, rcLen=0, tssLen=0, pkLen=0;
	BYTE* rcPtr;
	char data[EVP_CIPHER_block_size(EVP_aes_256_cbc()) * 16];
	struct stat stats;

	BIO *bdata = NULL, *b64 = NULL, *bmem = NULL;
	int bioRc = 0;
    int tssKeyDataSize = 0;
	int evpKeyDataSize = 0;

	/* Test for file existence */
	if ((rc = stat(IA_TPM_PLATFROM_KEY_PATH, &stats))) {
		LogError("Cannot find PlatfromKey.enc file");
        rc = IA_TPM_NOT_TSS_ERROR;
        goto out;
	}	

	/* Create an input file BIO */
	if((bdata = BIO_new_file(IA_TPM_PLATFROM_KEY_PATH, "r")) == NULL ) {
		LogError("Cannot open PlatfromKey.enc file");
        rc = IA_TPM_NOT_TSS_ERROR;
        goto out;
	}

	/* Test file header for TSS */
	BIO_gets(bdata, data, sizeof(data));
	if (strncmp(data, TPMSEAL_HDR_STRING, 
			strlen(TPMSEAL_HDR_STRING)) != 0) {
		LogError("PlatfromKey.enc has been destoried");
        rc = IA_TPM_NOT_TSS_ERROR;
        goto out;
	}		

	/* Looking for TSS Key Header */
	BIO_gets(bdata, data, sizeof(data));
	if (strncmp(data, TPMSEAL_TSS_STRING, 
			strlen(TPMSEAL_TSS_STRING)) != 0) {
		LogError("PlatfromKey.enc has been destoried");
        rc = IA_TPM_NOT_TSS_ERROR;
        goto out;
	}

	/* Create a memory BIO to hold the base64 TSS key */
	if ((bmem = BIO_new(BIO_s_mem())) == NULL) {
		LogError("Creating a memory BIO failed");
        rc = IA_TPM_NOT_TSS_ERROR;
        goto out;
	}
	BIO_set_mem_eof_return(bmem, 0);

	/* Read the base64 TSS key into the memory BIO */
	while ((rcLen = BIO_gets(bdata, data, sizeof(data))) > 0) {
		/* Look for EVP Key Header (end of key) */
		if (strncmp(data, TPMSEAL_EVP_STRING,
				strlen(TPMSEAL_EVP_STRING)) == 0)
			break;

		if (BIO_write(bmem, data, rcLen) <= 0) {
			LogError("Cannot write BIO memory when read TSS key from file");
            rc = IA_TPM_NOT_TSS_ERROR;
            goto out;
		}
	}
	if (strncmp(data, TPMSEAL_EVP_STRING, 
			strlen(TPMSEAL_EVP_STRING)) != 0 ) {
        LogError("PlatfromKey.enc has been destoried");
        rc = IA_TPM_NOT_TSS_ERROR;
        goto out;
	}

	/* Create a base64 BIO to decode the TSS key */
	if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        LogError("Create a base64 BIO failed before decode TSS key");
		rc = IA_TPM_NOT_TSS_ERROR;
        goto out;
	}

	/* Decode the TSS key */
	bmem = BIO_push( b64, bmem );
	while ((rcLen = BIO_read(bmem, data, sizeof(data))) > 0) {
		if ((tssLen + rcLen) > tssKeyDataSize) {
			tssKeyDataSize += TSSKEY_DEFAULT_SIZE;
			rcPtr = (BYTE*)realloc( sealKey, tssKeyDataSize);
			if ( rcPtr == NULL ) {
                LogError("Alloc memory failed when decode TSS key");
				rc = IA_TPM_NOT_TSS_ERROR;
                goto out;
			}
			sealKey = rcPtr;
		}
		memcpy(sealKey + tssLen, data, rcLen);
		tssLen += rcLen;
	}
    sealKeySize = tssLen;
	bmem = BIO_pop(b64);
	BIO_free(b64);
	b64 = NULL;
	bioRc = BIO_reset(bmem);
	if (bioRc != 1) {
		LogError("Reset BIO memory failed");
        rc = IA_TPM_NOT_TSS_ERROR;
        goto out; 
	}
	/* Read the base64 Symmetric key into the memory BIO */
	while ((rcLen = BIO_gets(bdata, data, sizeof(data))) > 0) {
		/* Look for Encrypted Data Header (end of key) */
		if (strncmp(data, TPMSEAL_FTR_STRING,
				strlen(TPMSEAL_FTR_STRING)) == 0)
			break;

		if (BIO_write(bmem, data, rcLen) <= 0) {
			LogError("Cannot write BIO memory when read PlatformKey from file");
            rc = IA_TPM_NOT_TSS_ERROR;
            goto out;
		}
	}

	/* Create a base64 BIO to decode the PlatformKey */
	if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
		LogError("Create a base64 BIO failed before decode PlatformKey");
		rc = IA_TPM_NOT_TSS_ERROR;
        goto out;
	}

	/* Decode the Symmetric key */
	bmem = BIO_push( b64, bmem );
	while ((rcLen = BIO_read(bmem, data, sizeof(data))) > 0) {
        printf("rcLen%d\n",rcLen);
		if ((pkLen + rcLen) > evpKeyDataSize) {
			evpKeyDataSize += TSSKEY_DEFAULT_SIZE;
			rcPtr = (BYTE*)realloc( sealedPK, evpKeyDataSize);
			if ( rcPtr == NULL ) {
				LogError("Alloc memory failed when decode PlatformKey");
				rc = IA_TPM_NOT_TSS_ERROR;
                goto out;
			}
			sealedPK = rcPtr;
		}
		memcpy(sealedPK + pkLen, data, rcLen);
		pkLen += rcLen;
	}
    sealedPKSize = pkLen;

    bmem = BIO_pop(b64);
	BIO_free(b64);
	b64 = NULL;
	/* a BIO_reset failure shouldn't have an affect at this point */
	bioRc = BIO_reset(bmem);
	if (bioRc != 1) {
        LogError("Clean up failed");
		goto out;
	}

out:
	if ( bdata )
		BIO_free(bdata);
	if ( b64 )
		BIO_free(b64);
	if ( bmem ) {
		bioRc = BIO_set_close(bmem, BIO_CLOSE);
		BIO_free(bmem);
	}
    return rc;
}

int ia_tpm_get_platform_key(TSS_HCONTEXT &hContext, UINT32 &PlatformKeySize, BYTE* &PlatformKey)
{
    TSS_HPOLICY     hPolicy, hSRKPolicy;
    TSS_HKEY        hKey, hSRK;
    TSS_HENCDATA    hEncData;

    BYTE            wellKnow[] = TSS_WELL_KNOWN_SECRET;
    BYTE*           sealKey = NULL;
    UINT32          sealKeySize = 0;
    BYTE*           sealedPK = NULL;
    UINT32          sealedPKSize = 0;

    int result;

    //Read PlatformKey.enc file.
    result = ia_tpm_read_PK_file(sealKey, sealKeySize, sealedPK, sealedPKSize);
    if (result == IA_TPM_NOT_TSS_ERROR)
    {
        LogError("Read PlatformKey.enc file failed");
        return result;
    }

    //Create EncData object for unseal PlatformKey.
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_SEAL, &hEncData);
    if (result != TSS_SUCCESS)
    {
        LogBug("Create EncData object", result);
        return result;
    }

    result = Tspi_SetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, sealedPKSize, sealedPK);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set EncData object data", result);
        return result;
    }

    //Create EncData object's policy.
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hPolicy);
    if (result != TSS_SUCCESS)
    {
        LogBug("Create EncData object policy", result);
        return result;
    }

    result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1, sizeof(wellKnow), wellKnow);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set EncData policy secret", result);
        return result;
    }

    //Assign policy to object
    result = Tspi_Policy_AssignToObject(hPolicy, hEncData);
    if (result != TSS_SUCCESS)
    {
        LogBug("Assign EncData policy to its object", result);
        return result;
    }

    //Load SRK.
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

    result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1, sizeof(wellKnow), wellKnow);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set SRK policy secret", result);
        return result;
    }

    //Load Key object of SealKey by SRK
    result = Tspi_Context_LoadKeyByBlob(hContext, hSRK, sealKeySize, sealKey, &hKey);
    if (result != TSS_SUCCESS)
    {
        LogBug("Load SealKey object", result);
        return result;
    }

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hPolicy);
    if (result != TSS_SUCCESS)
    {
        LogBug("Create SealKey object policy", result);
        return result;
    }

    result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1, sizeof(wellKnow), wellKnow);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set SealKey policy secret", result);
        return result;
    }

    result = Tspi_Policy_AssignToObject(hPolicy, hKey);
    if (result != TSS_SUCCESS)
    {
        LogBug("Assign policy to SealKey object", result);
        return result;
    }

    //Unseal PlatfromKey.
    result = Tspi_Data_Unseal(hEncData, hKey, &PlatformKeySize, &PlatformKey);
    if (result != TSS_SUCCESS)
    {
        LogBug("Unseal PlatformKey", result);
        return result;
    }

    return result;
}