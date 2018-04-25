#ifndef GRAD_PROJECT_GLOBAL_H
#define GRAD_PROJECT_GLOBAL_H

#define LogBug(s,e)     printf("\033[31m[ERROR]\033[0m%s:0x%08x\n",s,e);
#define LogError(s)     printf("\033[31m[ERROR]\033[0m%s\n",s);
#define LogInfo(s,i)    printf("\033[32m[LOG]\033[0m%s: %d\n",s,i);

#define CHECK(i)         printf("dome!%d\n",i);


#endif