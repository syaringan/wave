#include "wave.h"
#include<pthread.h>
#include<stdio.h>
#include<stdlib.h>
//#include"netlink_handle.h"
#define SERVICE "/var/tmp/wave_sec.socket"
static struct sec_db sec_db;
static void* wme_loop(void* sdb){
    //启动netlink，
    
    while(1){
    //阻塞接受数据
        sleep(3);
        printf("wme_serc\n");
    }
}
static int app_do_request(void *ptr){
    int fd = *((int*)ptr);
    struct sec_db* sdb = &sec_db;
    

};
static int app_start(struct sec_db* sdb){
    int fd,serve_fd;
    pthread_t tid;
    pthread_attr_t attr;
    if( (serve_fd = serv_listen(SERVICE)) < 0){
        return -1;
    }
    while(1){
        if( (fd = serv_accept(serv_fd,NULL)) < 0){
            return -1;
        }
        if( init_pthread_attr_t(&attr))
            return -1;
        if( pthread_create(&tid,&attr,app_do_request,(void*)&fd))
            return -1;
        pthread_attr_destroy(&attr);
    };
}
static int inline init_phtread_attr_t(pthread_attr_t* attr){
    if(pthread_attr_init(attr))
        return -1;
    if(pthread_attr_setdetachstate(attr,PTHREAD_CREATE_DETACHED))
        return -1;
    if( pthread_attr_setschedpolicy(attr,SCHED_FIFO))
        return -1;
    struct sched_param param;
    param.sched_priority = 60;
    if( pthread_attr_setschedparam(attr,&param))
        return -1;
    return 0;
}
static int inline init_wme_pthread_attr_t(pthread_attr_t* attr){
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
static struct sec_db* init_sec_db(){

    return &sdb;
}
int wave_start(){
    struct sec_db* sdb;
    int res;
    sdb = init_sec_db();
    if(sdb == NULL){
        return -1;
    }

    wme_serv_start(sdb);
    res = app_start(sdb);
    exit(res);
}
int wme_serv_start(struct sec_db* sdb){
   pthread_t wmes;
   pthread_attr_t attr;
   if(init_wme_pthread_attr_t(&attr))
        return -1;
   if(pthread_create(&wmes,&attr,wme_loop,(void*)sdb))
        return -1;
   pthread_attr_destroy(&attr);
   return 0;
}
