#ifndef GRAD_PROJECT_IA_TPM_H
#define GRAD_PROJECT_IA_TPM_H

#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_defines.h>
#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tspi.h>

//变量

//函数
/* 
 * 初始化 TPM
 */
int ia_tpm_init(
    TSS_HCONTEXT    &hContext,
    TSS_HTPM        &hTpm
);
/* 
 * 关闭 TPM
 */
int ia_tpm_close(
    TSS_HCONTEXT    &hContext,
    TSS_HTPM        &hTpm
);
/* 
 * Bind
 */
int ia_tpm_seal(
    TSS_HCONTEXT    &hContext,
    TSS_HKEY        hKey,
    UINT32          inSize,
    BYTE            *inData,
    UINT32          *outSize,
    BYTE            *outData,
    TSS_HPCRS       hPcrComposite
);

int ia_tpm_unseal(
    TSS_HCONTEXT    &hContext,
    TSS_HKEY        hKey,
    UINT32          inSize,
    BYTE            *inData,
    UINT32          *outSize,
    BYTE            *outData,
    TSS_HPCRS       hPcrComposite
);


int ia_tpm_get_srk(
    TSS_HCONTEXT    &hContext,
    TSS_HKEY        &hSRK,
    TSS_HPOLICY     &hSRKPolicy
);

int ia_tpm_creat_key(
    TSS_HCONTEXT    hContext,
    TSS_FLAG        initFlags,
    TSS_HKEY        &hParentKey,
    TSS_HKEY        &hKey
);


#endif