#ifndef GRAD_PROJECT_IA_TPM_H
#define GRAD_PROJECT_IA_TPM_H

#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_defines.h>
#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tspi.h>

//常量
#define IA_TPM_NOT_TSS_ERROR            -1
#define IA_TPM_PLATFROM_KEY_PATH        "./PlatformKey.enc"

#define TPMSEAL_HDR_STRING              "-----BEGIN TSS-----\n"
#define TPMSEAL_FTR_STRING              "-----END TSS-----\n"
#define TPMSEAL_TSS_STRING              "-----SEAL KEY-----\n"
#define TPMSEAL_EVP_STRING              "-----PLATFROM KEY-----\n"

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

int ia_tpm_seal_platform_key(
    TSS_HCONTEXT    &hContext,
    UINT32          PlatformKeySize,
    BYTE            *PlatformKey
);


#endif