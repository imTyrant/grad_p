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
    BYTE*           PlatformKey;
    UINT32          PlatformKeySize;

    int result;
    result = ia_tpm_init(hContext, hTpm);
    if (result != TSS_SUCCESS)
    {
        LogBug("[Main]tpm init",result);
        return -1;
    }

    result = ia_tpm_get_platform_key(hContext, PlatformKeySize, PlatformKey);
    if (result != TSS_SUCCESS)
    {
        LogBug("[Main]tpm unseal platform key", result);
        return -1;
    }
    printf("%d\n", PlatformKeySize);
    for(int i = 0; i < PlatformKeySize; i++)
    {
        printf("%c", PlatformKey[i]);
    }
    
    ia_tpm_close(hContext, hTpm);
    return 0;
}