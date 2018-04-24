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

int ia_tpm_seal(TSS_HCONTEXT &hContext, TSS_HKEY hKey, UINT32 inSize, BYTE *inData, UINT32 *outSize, BYTE *outData, TSS_HPCRS hPcrComposite)
{
    TSS_HPOLICY hPolicy;
    TSS_HENCDATA hEncData;
    UINT32 keySize, tpmOutSize;
    BYTE *tpmOut = 0;
    BYTE wellKnowSecret[] = TSS_WELL_KNOWN_SECRET;
    int result;

    //创建加密对象
    result = Tspi_Context_CreateObject(
        hContext,
        TSS_OBJECT_TYPE_ENCDATA,
        TSS_ENCDATA_SEAL,
        &hEncData);
    if (result != TSS_SUCCESS)
    {
        LogBug("Creat EncData object", result);
        return result;
    }
    //创建策略对象
    result = Tspi_Context_CreateObject(
        hContext,
        TSS_OBJECT_TYPE_POLICY,
        TSS_POLICY_USAGE,
        &hPolicy);
    if (result != TSS_SUCCESS)
    {
        LogBug("Creat policy object", result);
        return result;
    }
    //设置策略的秘密
    result = Tspi_Policy_SetSecret(
        hPolicy,
        TSS_SECRET_MODE_SHA1,
        sizeof(wellKnowSecret),
        wellKnowSecret);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set policy secret", result);
        return result;
    }
    //将策略与对象绑定
    result = Tspi_Policy_AssignToObject(
        hPolicy,
        hEncData);
    if (result != TSS_SUCCESS)
    {
        LogBug("Assign policy to object", result);
        return result;
    }
    //获取密钥长度
    result = Tspi_GetAttribUint32(
        hKey,
        TSS_TSPATTRIB_KEY_INFO,
        TSS_TSPATTRIB_KEYINFO_SIZE,
        &keySize);
    if (result != TSS_SUCCESS)
    {
        LogBug("Get key length", result);
        return result;
    }
    if (inSize > keySize - 16)
    {
        LogBug("Data to be binded is too big", 0);
        return result;
    }
    //获取加密数据块///////////////////////////////////////////////////////////////////////////////
    result = Tspi_Data_Seal(hEncData, hKey, inSize, inData, hPcrComposite);
    if (result != TSS_SUCCESS)
    {
        LogBug("Seal data", result);
        return result;
    }
    //获取加密数据
    result = Tspi_GetAttribData(
        hEncData,
        TSS_TSPATTRIB_ENCDATA_BLOB,
        TSS_TSPATTRIB_ENCDATABLOB_BLOB,
        &tpmOutSize,
        &tpmOut);
    if (result != TSS_SUCCESS)
    {
        LogBug("Get sealed data", result);
        return result;
    }
    printf("%d\t%d\t%d\n", tpmOutSize, *outSize, inSize);
    //输出
    outData = (BYTE *)malloc(tpmOutSize);
    memset(outData, 0, tpmOutSize);
    memcpy(outData, tpmOut, tpmOutSize);
    *outSize = tpmOutSize;
    //清理现场
    Tspi_Context_FreeMemory(hContext, tpmOut);
    Tspi_Context_CloseObject(hContext, hEncData);

    return result;
}

int ia_tpm_unseal(TSS_HCONTEXT &hContext, TSS_HKEY hKey, UINT32 inSize, BYTE *inData, UINT32 *outSize, BYTE *outData, TSS_HPCRS hPcrComposite)
{
    TSS_HENCDATA hEncData;
    TSS_HCONTEXT hPolicy;
    UINT32 keySize, tpmOutSize;
    BYTE *tpmOut = NULL;
    BYTE wellKnowSecret[] = TSS_WELL_KNOWN_SECRET;

    int result;

    //创建解密对象
    result = Tspi_Context_CreateObject(
        hContext,
        TSS_OBJECT_TYPE_ENCDATA,
        TSS_ENCDATA_SEAL,
        &hEncData);
    if (result != TSS_SUCCESS)
    {
        LogBug("Creat EncData object", result);
        return result;
    }
    //设置解密对象的数据
    result = Tspi_SetAttribData(
        hEncData,
        TSS_TSPATTRIB_ENCDATA_BLOB,
        TSS_TSPATTRIB_ENCDATABLOB_BLOB,
        inSize,
        inData);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set EncData object data", result);
        return result;
    }
    //创建策略对象
    result = Tspi_Context_CreateObject(
        hContext,
        TSS_OBJECT_TYPE_POLICY,
        TSS_POLICY_USAGE,
        &hPolicy);
    if (result != TSS_SUCCESS)
    {
        LogBug("Creat policy object", result);
        return result;
    }
    //设置策略的秘密
    result = Tspi_Policy_SetSecret(
        hPolicy,
        TSS_SECRET_MODE_SHA1,
        sizeof(wellKnowSecret),
        wellKnowSecret);
    if (result != TSS_SUCCESS)
    {
        LogBug("Set policy secret", result);
        return result;
    }
    //将策略与对象绑定
    result = Tspi_Policy_AssignToObject(
        hPolicy,
        hEncData);
    if (result != TSS_SUCCESS)
    {
        LogBug("Assign policy to object", result);
        return result;
    }
    //获取密钥长度
    result = Tspi_GetAttribUint32(
        hKey,
        TSS_TSPATTRIB_KEY_INFO,
        TSS_TSPATTRIB_KEYINFO_SIZE,
        &keySize);
    if (result != TSS_SUCCESS)
    {
        LogBug("Get key length", result);
        return result;
    }
    if (inSize > keySize - 16)
    {
        LogBug("Data to be unseal is too big", 0);
        return result;
    }
    //解密数据块
    result = Tspi_Data_Unseal(hEncData, hKey, &tpmOutSize, &tpmOut);
    if (result != TSS_SUCCESS)
    {
        LogBug("Unseal data", result);
        return result;
    }

    printf("%d\t%d\t%d\n", tpmOutSize, *outSize, inSize);
    //输出
    free(outData);
    outData = (BYTE *)malloc(tpmOutSize);
    memset(outData, 0, tpmOutSize);
    memcpy(outData, tpmOut, tpmOutSize);
    *outSize = tpmOutSize;
    //清理现场
    Tspi_Context_FreeMemory(hContext, tpmOut);
    Tspi_Context_CloseObject(hContext, hEncData);

    return result;
}

int ia_tpm_get_srk(TSS_HCONTEXT &hContext, TSS_HKEY &hSRK, TSS_HPOLICY &hSRKPolicy)
{
    BYTE wellKnowSecret[] = TSS_WELL_KNOWN_SECRET;
    int result;
    //获取SRK
    result = Tspi_Context_LoadKeyByUUID(
        hContext,
        TSS_PS_TYPE_SYSTEM,
        TSS_UUID_SRK,
        &hSRK);
    if (result != TSS_SUCCESS)
    {
        LogBug("Get SRK", result);
        return result;
    }
    //获取SRK策略
    result = Tspi_GetPolicyObject(
        hSRK,
        TSS_POLICY_USAGE,
        &hSRKPolicy);
    if (result != TSS_SUCCESS)
    {
        LogBug("Get SRK policy", result);
        return result;
    }
    //设置SRK策略
    result = Tspi_Policy_SetSecret(
        hSRKPolicy,
        TSS_SECRET_MODE_SHA1,
        sizeof(wellKnowSecret),
        wellKnowSecret
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Set SRK policy", result);
        return result;
    }
    return result;
}

/*
int ia_tpm_creat_key(TSS_HCONTEXT hContext, TSS_FLAG initFlags, TSS_HKEY &hParentKey, TSS_HKEY &hKey)
{
    int result;
    TSS_HPOLICY hPolicy;
    TSS_UUID hKeyUUID;

    //创建密钥对象
    result = Tspi_Context_CreateObject(
        hContext,
        TSS_OBJECT_TYPE_RSAKEY,
        initFlags,
        &hKey
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Create object", result);
        return result;
    }
    // //创建策略对象
    // result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,TSS_POLICY_USAGE, &hPolicy);
    // if (result != TSS_SUCCESS) {
    //     LogBug("Creat Key Policy Object", result);
    //     Tspi_Context_CloseObject(hContext, hKey);
    //     return result;
    // }
    
    //设置密钥的填充方式
    result = Tspi_SetAttribUint32(
        hKey,
        TSS_TSPATTRIB_KEY_INFO,
        TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
        TSS_ES_RSAESPKCSV15
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Set key Attribute", result);
        Tspi_Context_CloseObject(hContext, hKey);
        return result;
    }
    //创建密钥
    result = Tspi_Key_CreateKey(hKey, hParentKey, 0);
    if (result != TSS_SUCCESS)
    {
        LogBug("Create Key", result);
        Tspi_Context_CloseObject(hContext, hKey);
        return result;
    }
    //注册密钥
    result = Tspi_Context_RegisterKey(
        hContext,
        hKey,
        TSS_PS_TYPE_SYSTEM,
        hKeyUUID,
        TSS_PS_TYPE_SYSTEM,
        TSS_UUID_SRK
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Register key", result);
        Tspi_Context_CloseObject(hContext, hKey);
        return result;
    }

    return result;
}
*/

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