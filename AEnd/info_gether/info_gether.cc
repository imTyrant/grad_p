#include "../include/global.h"
#include "info_gether.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/statfs.h> 

float calc_usage(CPU_INFO &newInfo, CPU_INFO &oldInfo)
{
    float       newTotal, oldTotal;
    float       newIdle, oldIdle;
    //Calculate total cpu time firstly.
    newTotal = (float)(newInfo.user + newInfo.nice + newInfo.system 
                        + newInfo.idle + newInfo.iowait + newInfo.irq + newInfo.softirq);
    //Calculate total cpu time secondly
    oldTotal = (float)(oldInfo.user + oldInfo.nice + oldInfo.system 
                        + oldInfo.idle + oldInfo.iowait + oldInfo.irq + oldInfo.softirq);
    //Idle cputime.
    newIdle = (float)newInfo.idle;
    oldIdle = (float)oldInfo.idle;

    //Get usage of cpu time.
    return 100.0 - (newIdle - oldIdle)/(newTotal - oldTotal) * 100.0;
}
int get_stat_detail(CPU_INFO &cpuInfo)
{
    FILE*       fp;
    char        buffer[256] = {0};
    int         result;

    //Open cpu file.
    fp = fopen(SYS_CPU_INFO_PATH, FILE_READ_ONLY);
    if (fp == NULL)
    {
        LogError("Cannot open /proc/stat");
        return INFO_GETHER_E_ERROR_OCCURE;
    }

    //Get first line of /proc/stat.
    fgets(buffer, sizeof(buffer), fp);
    sscanf (buffer, "%s %u %u %u %u %u %u %u", &cpuInfo.name, &cpuInfo.user,&cpuInfo.nice, 
            &cpuInfo.system, &cpuInfo.idle,&cpuInfo.iowait, &cpuInfo.irq, &cpuInfo.softirq);
    
    fclose(fp);
    return INFO_GETHER_SUCCESS;
}

int info_gether_cpu(float &cpuUsage)
{
    CPU_INFO        newInfo;
    CPU_INFO        oldInfo;
    int             result;
    
    //Open /proc/stat file and read.
    if (INFO_GETHER_SUCCESS != get_stat_detail(newInfo))
    {
        return INFO_GETHER_E_ERROR_OCCURE;
    }

    //Wait until stat refreshed.
    usleep(CPU_CATCH_REFRESH_TIME);

    //Open /proc/stat file and read again.
    if (INFO_GETHER_SUCCESS != get_stat_detail(oldInfo))
    {
        return INFO_GETHER_E_ERROR_OCCURE;
    }

    cpuUsage = calc_usage(newInfo, oldInfo);
    return INFO_GETHER_SUCCESS;
}

int info_gether_mem(float &memUsage)
{
    FILE*               fp;
    MEM_INFO            memInfo;
    char                buffer[256];
    unsigned long       memTotal;
    unsigned long       memFree;

    fp = fopen(SYS_MEM_INFO_PATH, FILE_READ_ONLY);
    if (fp == NULL)
    {
        LogError("Open /proc/meminfo failed");
        return INFO_GETHER_E_ERROR_OCCURE;
    }
    
    fgets(buffer, sizeof(buffer), fp);
    sscanf(buffer, "%s %lu %s\n", &memInfo.preStr, &memInfo.num, &memInfo.postStr);
    memTotal = memInfo.num;

    // memset(buffer, 0, sizeof(buffer));

    fgets(buffer, sizeof(buffer), fp);
    sscanf(buffer, "%s %lu %s\n", &memInfo.preStr, &memInfo.num, &memInfo.postStr);
    memFree = memInfo.num;

    fclose(fp);

    memUsage = 100.0 - (float)memFree/(float)memTotal * 100.0;
    return INFO_GETHER_SUCCESS;
}


int info_gether_sys(SYS_INFO &sysInfo)
{
    FILE*       fp;

    memset(&sysInfo, 0, sizeof(SYS_INFO));
    //Get system kernel version
    fp = fopen(SYS_MEM_INFO_KERNEL, FILE_READ_ONLY);
    if (fp == NULL)
    {
        LogError("Cannot open /proc/sys/kernel/version");
        return INFO_GETHER_E_ERROR_OCCURE;
    }
    fgets(sysInfo.kernel, sizeof(sysInfo.kernel), fp);
    fclose(fp);

    //Get system release version
    fp = fopen(SYS_MEM_INFO_RELEASE, FILE_READ_ONLY);
    if (fp == NULL)
    {
        LogError("Cannot open /proc/sys/kernel/osrelease");
        return INFO_GETHER_E_ERROR_OCCURE;
    }
    fgets(sysInfo.release, sizeof(sysInfo.release), fp);
    fclose(fp);

    //Get system type
    fp = fopen(SYS_MEM_INFO_OS_TYPE, FILE_READ_ONLY);
    if (fp == NULL)
    {
        LogError("Cannot open /proc/sys/kernel/ostype");
        return INFO_GETHER_E_ERROR_OCCURE;
    }
    fgets(sysInfo.os, sizeof(sysInfo.os), fp);
    fclose(fp);

    return INFO_GETHER_SUCCESS;
}

int info_gether_net(NET_INFO** netInfo, int &netPortNum)
{
    FILE* fp;

    int i = 0;
    char buff[256] = {0};

    fp = fopen("/proc/net/tcp", FILE_READ_ONLY);
    if (fp == NULL)
    {
        LogError("Cannot open /proc/net/tcp");
        return INFO_GETHER_E_ERROR_OCCURE;
    }

    fgets(buff, sizeof(buff), fp);

    while(!feof(fp) && (i < MAX_NET_PORT_NUM))
    {
        memset(buff, 0, sizeof(buff));
        netInfo[i] = (NET_INFO*)malloc(sizeof(NET_INFO));
        fgets(buff, sizeof(buff), fp);
        sscanf(buff, "%*s%s%s%s", &(netInfo[i]->loacl), &(netInfo[i]->remote), &(netInfo[i]->status));
        i++;
    }
    fclose(fp);
    netPortNum = i;
    return INFO_GETHER_SUCCESS;
}

int info_gether_disk(float &diskUsage)
{
    struct statfs diskInfo;

    if (statfs("/", &diskInfo))
    {
        LogError("Get disk info failed");
        return INFO_GETHER_E_ERROR_OCCURE;
    }

    diskUsage = 100.0 - ((float)diskInfo.f_bavail / (float)diskInfo.f_blocks) * 100.0;
    return INFO_GETHER_SUCCESS;
}