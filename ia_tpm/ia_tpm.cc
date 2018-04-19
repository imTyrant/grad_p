#include "ia_tpm.h"

int ia_tpm_init()
{
    TSS_HCONTEXT hContext;
    int result;
    result = Tspi_Context_Create(&hContext);
    return result;
}