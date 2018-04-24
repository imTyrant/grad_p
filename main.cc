#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/global.h"
#include "ia_tpm/ia_tpm.h"

BYTE source[12] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};

BYTE testData[] = "1234567";

int main(int argc, char** argv)
{
    TSS_HCONTEXT    hContext;
    TSS_HTPM        hTpm; 
    TSS_HKEY        hSRK;
    TSS_HPOLICY     hSRKPolicy;

    int result;
    result = ia_tpm_init(hContext, hTpm);
    if (result != TSS_SUCCESS)
    {
        LogBug("[Main]tpm init",result);
        return -1;
    }
    result = ia_tpm_seal_platform_key(hContext, 7, testData);
    if (result != TSS_SUCCESS)
    {
        LogBug("[Main]tpm seal platform key", result);
        return -1;
    }
    /*
    result = ia_tpm_get_srk(hContext, hSRK, hSRKPolicy);
    if (result != TSS_SUCCESS)
    {
        LogBug("Get SRK",result);
        return -1;
    }

    UINT32 inSize;
    UINT32 outSize;
    BYTE *outData;
    inSize = 12;
    outData = (BYTE*)malloc(inSize);
    memset(outData, 0, 12);

    result = ia_tpm_seal(hContext, hSRK, inSize, source, &outSize, outData, 0);
    if (result != TSS_SUCCESS)
    {
        LogBug("[Main]Seal data",result);
        return -1;
    }
    printf("%d\n", outSize);

    result = ia_tpm_unseal(hContext, hSRK, outSize, outData, &outSize, outData, 0);
    if (result != TSS_SUCCESS)
    {
        LogBug("[Main]Unseal data",result);
        return -1;
    }
    for(int i =0; i < outSize; i++)
    {
        printf("%02x",outData[i]);
    }
    printf("\n");
    Tspi_Context_CloseObject(hContext, hSRK);
    Tspi_Context_CloseObject(hContext, hSRKPolicy);
    */
    ia_tpm_close(hContext, hTpm);
    return 0;
}