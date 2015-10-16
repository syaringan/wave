#include "wave.h"
#include<pthread.h>
#include<stdio.h>
#include<stdlib.h>
//#include"netlink_handle.h"
static void* wme_loop(void* sdb){
    //启动netlink，
    //阻塞接受数据
    
    while(1){
        sleep(3);
        printf("wme_serc\n");
    }
}
static void app_loop(struct sec_db* sdb){
    while(1){
    
    };
}
static int inline init_pthread_attr_t(pthread_attr_t* attr){
   if(pthread_attr_init(attr))
        return -1;
   if(pthread_attr_setdetachstate(attr,PTHREAD_CREATE_DETACHED))
        return -1;
   if( pthread_attr_setschedpolicy(attr,SCHED_RR))
        return -1;
   struct sched_param param;
   param.sched_priority = 60;
   if( pthread_attr_setschedparam(attr,&param))
        return -1;
   return 0;
}
int wme_serv_start(struct sec_db* sdb){
   pthread_t wmes;
   pthread_attr_t attr;
   if(init_pthread_attr_t(&attr))
        return -1;
   if(pthread_create(&wmes,&attr,wme_loop,(void*)sdb))
        return -1;
   pthread_attr_destroy(&attr);
   app_loop(sdb);
   return 0;
}
