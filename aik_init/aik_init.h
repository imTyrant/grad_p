#ifndef GRAD_PROJECT_AIK_INIT_H
#define GRAD_PROJECT_AIK_INIT_H

#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_defines.h>
#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tspi.h>

//常量
#define PRIVACY_CA_PUB_KEY_PATH     "./rsa_public_key.pem"
#define REQUIRE_FILE_PATH           "./req"

int aik_init_create_aik(
    TSS_HCONTEXT    &hContext,
    TSS_HTPM        &hTpm
);


#endif