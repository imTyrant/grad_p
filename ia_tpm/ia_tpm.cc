#include "ia_tpm.h"
#include "../include/global.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <trousers/trousers.h>


int ia_tpm_init(TSS_HCONTEXT &hContext, TSS_HTPM &hTpm)
{
    int result;
    //创建TSS上下文对象
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS)
    {
        LogBug("Tspi Context Creation",result);
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

    // result = Tspi_Context_Close(hTpm);
    // if (result != TSS_SUCCESS)
    // {
    //     LogBug("Close TPM handle", result);
    // }
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
    TSS_HPOLICY     hPolicy;
    TSS_HENCDATA    hEncData;
    UINT32          keySize, tpmOutSize;
    BYTE            *tpmOut = 0;
    BYTE            wellKnowSecret[] = TSS_WELL_KNOWN_SECRET;
    int             result;

    //创建加密对象
    result = Tspi_Context_CreateObject(
        hContext,
        TSS_OBJECT_TYPE_ENCDATA,
        TSS_ENCDATA_SEAL,
        &hEncData
    );
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
        &hPolicy
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Creat policy object", result);
        return result;
    }
    //设置策略的秘密
    result = Tspi_Policy_SetSecret(
        hPolicy,
        TSS_SECRET_MODE_PLAIN,
	    sizeof(wellKnowSecret),
        wellKnowSecret
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Set policy secret", result);
        return result;
    }
    //将策略与对象绑定
    result = Tspi_Policy_AssignToObject(
        hPolicy,
        hEncData
    );
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
        &keySize
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Get key length", result);
        return result;
    }
    if(inSize > keySize - 16)
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
        &tpmOut
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Get sealed data", result);
        return result;
    }
    printf("%d\t%d\t%d\n", tpmOutSize, *outSize, inSize);
    //输出
    outData = (BYTE*)malloc(tpmOutSize);
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
        &hEncData
    );
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
        inData
    );
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
        &hPolicy
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Creat policy object", result);
        return result;
    }
    //设置策略的秘密
    result = Tspi_Policy_SetSecret(
        hPolicy,
        TSS_SECRET_MODE_PLAIN,
	    sizeof(wellKnowSecret),
        wellKnowSecret
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Set policy secret", result);
        return result;
    }
    //将策略与对象绑定
    result = Tspi_Policy_AssignToObject(
        hPolicy,
        hEncData
    );
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
        &keySize
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Get key length", result);
        return result;
    }
    if(inSize > keySize - 16)
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
    outData = (BYTE*)malloc(tpmOutSize);
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
        &hSRK
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Get SRK", result);
        return result;
    }
    //获取SRK策略
    result = Tspi_GetPolicyObject(
        hSRK,
        TSS_POLICY_USAGE,
        &hSRKPolicy
    );
    if (result != TSS_SUCCESS)
    {
        LogBug("Get SRK policy", result);
        return result;
    }
    //设置SRK策略
    // result = Tspi_Policy_SetSecret(
    //     hSRKPolicy,
    //     TSS_SECRET_MODE_PLAIN,
    //     sizeof(wellKnowSecret),
    //     wellKnowSecret
    // );
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

