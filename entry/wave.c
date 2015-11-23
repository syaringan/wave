#include "wave.h"
#include<pthread.h>
#include<stdio.h>
#include<stdlib.h>
#include"netlink.h"
#include "../sec/sec.h"
#define SERVICE "/var/tmp/wave_sec.socket"
#define INIT(m) memset(&m, 0, sizeof(m));
#define RECV_HEAD_LEN 14

static struct sec_db sec_db;
static void* wme_loop(void* sdb){
    //启动netlink，
    int ret = 0;
    int recv_data_len = 0;//接收到的整个数据报文的长度
    int permission_len = 0;//permission报文的长度
    char rbuf[MAX_PAYLOAD];//接收报文缓冲区
    struct nlmsghdr nlh;
    struct msghdr msg;
    struct wme_tobe_signed_wsa head;//接收到的报文头部
    struct permission per;//解析出来的permission数组
    serviceinfo_array permissions;//需要填充的permission数组
    time32 life_time;
    string wsa;//接收到的wsa数据部分
    result ret;

    int fd = dot2_init_netlink(&nlh, &msg);
    if(fd < 0){
        wave_error_printf("netlink初始化失败");
        return;
    }
    while(1){
        memset((char*)NLMSG_DATA(nlh, 0, MAX_PAYLOAD));
        memset(rbuf, 0, MAX_PAYLOAD);
        INIT(permissions);
        INIT(wsa);

        ret = recvmsg(fd, &msg, 0);
        if(ret < 0){
            wave_error_printf("接收netlink消息失败");
            return;
        }
        recv_data_len = nlh.nlmsg_len;
        memcpy(rbuf, NLMSG_DATA(&nlh), recv_data_len);

        //解析报文
        char *shift = rbuf;
        memcpy(&head, shift, RECV_HEAD_LEN);
        life_time = head.lifetime;
        shift += RECV_HEAD_LEN;

        wsa.len = head.wsa_len;
        wsa.buf = malloc(wsa.len);
        if(!wsa.buf){
            wave_malloc_error();
            return;
        }
        memcpy(wsa.buf, shift, wsa.len);
        shift += wsa.len;

        permission_len = recv_data_len - RECV_HEAD_LEN - wsa.len;

        permissions.len = 0;
        permissions.serviceinfos = malloc(sizeof(serviceinfo)*32);//分配32个为最大的长度
        while(permission_len > 0){
            memcpy(&per, shift, 4);
            shift += 4;

            memcpy(&permissions.serviceinfos[permissions.len].max_priority, &per.priority, 1);

            char *le_psid = malloc(sizeof(char)*per.psid_len);
            if(!le_psid){
                wave_malloc_error();
                return;
            }
            memcpy(le_psid, shift, per.psid_len);
            psid_be_2_le(le_psid, per.psid_len);
            memcpy(&permissions.serviceinfos[permissions.len].psid, le_psid, psid_len);
            free(ls_psid);
            shift += per.psid_len;

            if(per.ssp_len > 0){
                permissions.serviceinfos[permissions.len].ssp.len = per.ssp_len;
                permissions.serviceinfos[permissions.len].ssp.buf = malloc(per.ssp_len);
                if(!permissions.serviceinfos[permissions.len].ssp.buf){
                    wave_malloc_error();
                    return;
                }
                memcpy(permissions.serviceinfos[permissions.len].ssp.buf, shift, per.ssp_len);
            }
            shift = shift + per.ssp_len + per.pssi_len;

            permissions.len++;
            permission_len = permission_len - per.psid_len - per.ssp_len - per.pssi_len - 4;
        }
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
