#ifndef GRAD_PROJECT_INFO_GETHER
#define GRAD_PROJECT_INFO_GETHER

//宏定义
#define INFO_GETHER_SUCCESS                 0
#define INFO_GETHER_E_ERROR_OCCURE          -1
#define INFO_GETHER_E_SYS_FILE              0x2

#define MAX_NET_PORT_NUM                    256

#define FILE_READ_ONLY              "r"
#define SYS_CPU_INFO_PATH           "/proc/stat"
#define CPU_CATCH_REFRESH_TIME      500*1000        //Microseconds of refreshing when gether cpu info.

#define SYS_MEM_INFO_PATH           "/proc/meminfo"

#define SYS_MEM_INFO_KERNEL         "/proc/sys/kernel/version"
#define SYS_MEM_INFO_RELEASE        "/proc/sys/kernel/osrelease"
#define SYS_MEM_INFO_OS_TYPE        "/proc/sys/kernel/ostype"


//变量定义
typedef struct _CPU_INFO  
{  
    char            name[20];              
    unsigned int    user;          
    unsigned int    nice;         
    unsigned int    system;      
    unsigned int    idle;         
    unsigned int    iowait;  
    unsigned int    irq;  
    unsigned int    softirq;  
}CPU_INFO;

typedef struct _MEM_INFO
{
    char            preStr[40];
    unsigned long   num;
    char            postStr[40];
}MEM_INFO;

typedef struct _SYS_INFO
{
    char    os[80];
    char    release[80];
    char    kernel[80];
}SYS_INFO;

typedef struct _NET_INFO
{
    char    loacl[14];
    char    remote[14];
    char    status[3];
}NET_INFO;

//函数

/*
 * 搜集CPU的使用率
 */
int
info_gether_cpu(
    float       &cpuUsage
);

/*
 * 搜集内存的使用率
 */
int
info_gether_mem(
    float       &memUsage
);

/*
 * 搜集系统的使用率
 */
int 
info_gether_sys(
    SYS_INFO    &sysInfo
);

/*
 * 搜集网络端口的开放情况
 */
int
info_gether_net(
    NET_INFO**  netInfo,
    int         &netPortNum
);
/*
 * 搜集磁盘使用率
 */
int
info_gether_disk(
    float       &diskUsage
);

#endif