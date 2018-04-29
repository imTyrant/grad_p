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

#define TSSKEY_DEFAULT_SIZE             768
#define SYSKEY_DEFAULT_SIZE             365
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
 * 封装密钥
 */
int ia_tpm_seal_key(
    TSS_HCONTEXT    &hContext,
    const char*     SealedKeyPath,
    UINT32          KeySize,
    BYTE*           Key
);
/* 
 * 封装PlatformKey到本地
 */
int ia_tpm_seal_platform_key(
    TSS_HCONTEXT    &hContext,
    UINT32          PlatformKeySize,
    BYTE            *PlatformKey
);
/*
 * 从本地读取已经封装好的密钥
 */
int ia_tpm_get_key(
    TSS_HCONTEXT    &hContext,
    const char*     keyPath,
    UINT32          &KeySize,
    BYTE*           &Key
);
/*
 * 从本地读取PlatformKey
 */
int ia_tpm_get_platform_key(
    TSS_HCONTEXT    &hContext,
    UINT32          &PlatformKeySize,
    BYTE*           &PlatformKey
);

#endif