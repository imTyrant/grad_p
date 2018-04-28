#ifndef GRAD_PROJECT_GLOBAL_H
#define GRAD_PROJECT_GLOBAL_H

#define LogBug(s,e)     printf("\033[31m[ERROR]\033[0m%s:0x%08x\n",s,e);
#define LogError(s)     printf("\033[31m[ERROR]\033[0m%s\n",s);
#define LogInfo(s,i)    printf("\033[32m[LOG]\033[0m%s: %d\n",s,i);

#define CHECK(i)         printf("dome!%d\n",i);

#define ST      0x0
#define T       0x1
#define D       0x2
#define UT      0x4


#define TRUST_CERTIFICATE_PATH             "./tc"

#define CA_PUB_KEY_SOUCRE_PATH       "./rsa_public_key.pem"
#define PLATFORM_KEY_SOUCRCE_PATH    "./PlatformKey.dec"

#define PLATFORM_KEY_ENC_PATH        "./PlatformKey.enc"
#define CA_PUB_KEY_ENC_PATH          "./rsa_public_key.enc"

#define PLATFROM_KEY_LEN        7
#define HASH_SECHEME_SHA1       20

typedef struct _REPO_GRAM_HEAD
{
    unsigned int  head;
    unsigned int  dataLength;
}REPO_GRAM_HEAD;

#endif