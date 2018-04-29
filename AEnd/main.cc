#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "include/global.h"
#include "ia_tpm/ia_tpm.h"
#include "info_gether/info_gether.h"
#include "aik_init/aik_init.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

#include <sys/time.h>
//函数
int check_sign(TRUSTED_CERT &cert, UINT32 signLen, BYTE* sign);
RSA* get_ca_pub_key();
int repo_ST(UINT32 &repoSize, BYTE* &repo);
int repo_T(UINT32 &repoSize, BYTE* &repo);
int report_form(UINT32 &gramSize, BYTE* &gram, UINT32 repoSize, BYTE* repo);

//变量
int currLevel = T;

BYTE testData[] = "1234567abcdef";

int main(int argc, char** argv)
{   
    struct timeval  start, end;

    TSS_HCONTEXT    hContext;
    TSS_HTPM        hTpm;

    BYTE*           PlatformKey;
    UINT32          PlatformKeySize;

    struct stat     stats;
    int             result;

    result = ia_tpm_init(hContext, hTpm);
    if (result != TSS_SUCCESS)
    {
        LogBug("[Main]TPM init",result);
        return -1;
    }

    if ((result = stat(CA_PUB_KEY_SOUCRE_PATH, &stats)))
    {
        LogError("[Main]Can't find CA pub key.");
        goto error_out;
    }

    if ((result = stat(PLATFORM_KEY_ENC_PATH, &stats)))
    {
        if ((result = stat(PLATFORM_KEY_SOUCRCE_PATH, &stats)))
        {
            LogError("[Main]Cannot find encrypted PlatformKey or raw PlatformKey");
            goto error_out;
        }

        FILE*   fp = fopen(PLATFORM_KEY_SOUCRCE_PATH, "rb");
        BYTE    buffer[256];
        UINT32  getSize;
        getSize = fread((char*)buffer, sizeof(BYTE), sizeof(buffer), fp);
        if (getSize != PLATFROM_KEY_LEN)
        {
            LogError("[Main]Invalid PlatformKey file.")
            goto error_out;
        }

        result = ia_tpm_seal_platform_key(hContext, getSize, buffer);
        if (result != TSS_SUCCESS)
        {
            LogBug("[Main]Seal PlatformKey to local.",result);
            goto error_out;
        }
    }

    BYTE*   repo;
    UINT32  repoSize;

    if((result = stat(TRUST_CERTIFICATE_PATH, &stats)))
    {
        if (INFO_GETHER_SUCCESS != repo_T(repoSize, repo))
        {
            LogError("[Main]Gether info failed");
            goto error_out;
        }
        
        //Attestation
        BYTE*   gram;
        UINT32  gramSize;
        report_form(gramSize, gram, repoSize, repo);
        FILE* fp = fopen("./report","wb");
        fwrite(gram, sizeof(BYTE), gramSize, fp);
        fclose(fp);
    }

    
    int j;
    j = 10;
    while(j--)
    {
        j = 0;
        switch(currLevel)
        {
            case ST:
                if (INFO_GETHER_SUCCESS != repo_ST(repoSize, repo))
                {
                    LogError("[Main]Gether info failed");
                    goto error_out;
                }
                break;
            case T:
                if (INFO_GETHER_SUCCESS != repo_T(repoSize, repo))
                {
                    LogError("[Main]Gether info failed");
                    goto error_out;
                }
                break;
            case D:
                break;
            case UT:
                break;
            default:
                LogError("[Main]Error! Unknown status level.")
                break;
        }

        BYTE*   gram;
        UINT32  gramSize;
        report_form(gramSize, gram, repoSize, repo);
        FILE* fp = fopen("./report","wb");
        fwrite(gram, sizeof(BYTE), gramSize, fp);
        fclose(fp);
        free(repo);
        free(gram);

        BYTE    sign[512];
        UINT32  cerLen;
        TRUSTED_CERT tc;
        UINT32  signLen;

        fp = fopen("./tc", "rb");
        fread(&cerLen, sizeof(BYTE), sizeof(int), fp);
        fread(&tc, sizeof(BYTE), sizeof(tc), fp);
        signLen =  fread(sign, sizeof(BYTE), 512, fp);
        fclose(fp);
        
        gettimeofday( &start, NULL );
        if (check_sign(tc, signLen, sign))
        {
            printf("same\n");
        }
        else
        {
            printf("unsame\n");
        }

        gettimeofday( &end, NULL );
        int timeuse;
        timeuse = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec -start.tv_usec;
        printf("time: %d us\n", timeuse);

        printf("%d,%d,%d,%d\n", tc.id, tc.status, tc.reTime, tc.ToV);
        switch(tc.status)
        {
            case 0x0:
                currLevel = ST;
                break;
            case 0x1:
                currLevel = T;
                break;
            case 0x2:
                currLevel = D;
                break;
            default:
                currLevel = UT;
                break;
        }
        currLevel = tc.status;

        //Form report

        //Attestation
    }
    

    // result = ia_tpm_seal_platform_key(hContext, sizeof(testData), testData);
    // if (result != TSS_SUCCESS)
    // {
    //     LogBug("[Main]tpm init",result);
    //     return -1;
    // }

    // result = ia_tpm_get_platform_key(hContext, PlatformKeySize, PlatformKey);
    // if (result != TSS_SUCCESS)
    // {
    //     LogBug("[Main]tpm unseal platform key", result);
    //     return -1;
    // }
    // printf("%d\n", PlatformKeySize);
    // for(int i = 0; i < PlatformKeySize; i++)
    // {
    //     printf("%c", PlatformKey[i]);
    // }
    // printf("\n");
out:
    ia_tpm_close(hContext, hTpm);
    return 0;

error_out:
    ia_tpm_close(hContext, hTpm);
    return -1;
}

int check_sign(TRUSTED_CERT &cert, UINT32 signLen, BYTE* sign)
{
    RSA*    ca_rsa;
    SHA_CTX sha_ctx = { 0 };
    unsigned char digest[SHA_DIGEST_LENGTH];
    int rc;

    rc = SHA1_Init(&sha_ctx);

    rc = SHA1_Update(&sha_ctx, &cert, sizeof(cert));

    rc = SHA1_Final(digest, &sha_ctx);

    ca_rsa = get_ca_pub_key();
    rc = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, sign, signLen, ca_rsa);
    RSA_free(ca_rsa);

    return rc;
}

int report_form(UINT32 &gramSize, BYTE* &gram, UINT32 repoSize, BYTE* repo)
{
    BYTE           Hash[HASH_SECHEME_SHA1];
    REPO_GRAM_HEAD  gramHead;
    SHA_CTX         s;

    gram = (BYTE*)malloc(repoSize + sizeof(REPO_GRAM_HEAD) + 20);

    SHA1_Init(&s);
    SHA1_Update(&s, repo, repoSize);
    SHA1_Final(Hash, &s);

    gramHead.head = 0x0;
    gramHead.dataLength = repoSize;

    memcpy(gram, &gramHead, sizeof(gramHead));
    memcpy(gram + sizeof(gramHead), repo, repoSize);
    memcpy(gram + sizeof(gramHead) + repoSize, Hash, HASH_SECHEME_SHA1);

    gramSize = sizeof(gramHead) + repoSize + HASH_SECHEME_SHA1;

    return 0;
}

void openssl_print_errors()
{
    ERR_load_ERR_strings();
    ERR_load_crypto_strings();
    ERR_print_errors_fp(stderr);
}

RSA* get_ca_pub_key()
{
    BIO*    b = NULL;
    RSA*    rsa = NULL;

    b = BIO_new_file(CA_PUB_KEY_SOUCRE_PATH, "r");
    if (b == NULL) 
    {
        fprintf(stderr, "Error opening file for read: %s\n", CA_PUB_KEY_SOUCRE_PATH);
        return NULL;
    }

    if ((rsa = PEM_read_bio_RSA_PUBKEY(b, NULL, 0, NULL)) == NULL) {
        fprintf(stderr, "Reading key %s from disk failed.\n", CA_PUB_KEY_SOUCRE_PATH);
        openssl_print_errors();
    }
    BIO_free(b);

    return rsa;
}

int repo_ST(UINT32 &repoSize, BYTE* &repo)
{
    SYS_INFO    sysInfo;
    repoSize = sizeof(SYS_INFO);
    if (INFO_GETHER_SUCCESS != info_gether_sys(sysInfo))
    {
        return INFO_GETHER_E_ERROR_OCCURE;
    }
    repo = (BYTE*)malloc(repoSize);
    memcpy(repo, &sysInfo, repoSize);
    return INFO_GETHER_SUCCESS;
}

int repo_T(UINT32 &repoSize, BYTE* &repo)
{
    SYS_INFO    sysInfo;
    NET_INFO*   netInfo[MAX_NET_PORT_NUM];

    float       cpuUsage, memUsage, diskUsage;
    int         portNum;

    if (INFO_GETHER_SUCCESS != info_gether_sys(sysInfo))
    {
        return INFO_GETHER_E_ERROR_OCCURE;
    }
    if (INFO_GETHER_SUCCESS != info_gether_cpu(cpuUsage))
    {
        return INFO_GETHER_E_ERROR_OCCURE;
    }
    if (INFO_GETHER_SUCCESS != info_gether_mem(memUsage))
    {
        return INFO_GETHER_E_ERROR_OCCURE;
    }
    if (INFO_GETHER_SUCCESS != info_gether_disk(diskUsage))
    {
        return INFO_GETHER_E_ERROR_OCCURE;
    }
    if (INFO_GETHER_SUCCESS != info_gether_net(netInfo, portNum))
    {
        return INFO_GETHER_E_ERROR_OCCURE;
    }

    repoSize = sizeof(SYS_INFO) + sizeof(cpuUsage) + sizeof(cpuUsage) + 
                    sizeof(cpuUsage) + sizeof(portNum) + portNum * sizeof(NET_INFO);
    repo = (BYTE*)malloc(repoSize);
    
    BYTE*   ir = repo;
    memcpy(ir, &sysInfo, sizeof(sysInfo));
    ir += sizeof(sysInfo);
    memcpy(ir, &cpuUsage, sizeof(cpuUsage));
    ir += sizeof(cpuUsage);
    memcpy(ir, &memUsage, sizeof(memUsage));
    ir += sizeof(memUsage);
    memcpy(ir, &diskUsage, sizeof(diskUsage));
    ir += sizeof(diskUsage);
    memcpy(ir, &portNum, sizeof(portNum));
    ir += sizeof(portNum);
    for (int i = 0; i < portNum; i++)
    {
        memcpy(ir, netInfo[i], sizeof(NET_INFO));
        ir += sizeof(NET_INFO);
    }
    
    return INFO_GETHER_SUCCESS;
}