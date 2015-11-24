#include "wave.h"
#include<pthread.h>
#include<stdio.h>
#include<stdlib.h>
#include"netlink.h"
#include "../sec/sec.h"
#define SERVICE "/var/tmp/wave_sec.socket"
#define INIT(m) memset(&m, 0, sizeof(m));
#define RECV_S_HEAD_LEN 15
#define RECV_V_HEAD_LEN 12 
static struct sec_db sec_db;
static void* wme_loop(void* sdb){
    //启动netlink，
    int i = 0;
    int recv_data_len = 0;//接收到的整个数据报文的长度
    char sbuf[MAX_PAYLOAD];//发送报文缓冲区
    char rbuf[MAX_PAYLOAD];//接收报文缓冲区
    struct nlmsghdr nlh;
    struct msghdr msg;
    result ret;
    /*
     * 签名请求需要用到的参数
     * */
    struct wme_tobe_signed_wsa s_head;//接收到的需要签名报文头部
    struct signed_wsa s_wsa;
    int permission_len = 0;//permission部分报文的长度
    struct permission per;
    string unsigned_wsa;//接收到的wsa数据部分
    serviceinfo_array permissions;//需要填充的permission数组
    time32 life_time;

    string signed_wsa;
    /*
     * 验证请求需要用到的参数
     * */
    struct dot2_tobe_verified_wsa v_head;//接收到的需要验证的报文头部
    struct verified_wsa v_wsa;//验证成功需要发送给内核的报文头部
    string unverified_wsa;

    result_array results;
    string wsa_data;
    ssp_array ssp_array;
    time64_with_standard_deviation generation_time;
    time64 expiry_time;
    three_d_location location;
    struct time32_array last_crl_time;
    struct time32_array next_crl_time;
    certificate cert;

    int fd = dot2_init_netlink(&nlh, &msg);
    if(fd < 0){
        wave_error_printf("netlink初始化失败");
        return;
    }
    while(1){
        memset((char*)NLMSG_DATA(nlh, 0, MAX_PAYLOAD));
        memset(rbuf, 0, MAX_PAYLOAD);
        INIT(permissions);
        INIT(unsigned_wsa);
        INIT(signed_wsa);

        ret = recvmsg(fd, &msg, 0);
        if(ret < 0){
            wave_error_printf("接收netlink消息失败");
            goto destructor;
        }
        recv_data_len = nlh.nlmsg_len;
        memcpy(rbuf, NLMSG_DATA(&nlh), recv_data_len);

        //解析报文
        char *shift = rbuf;
        //0为签名
        if(*shift = 0){
            memcpy(&s_head, shift, RECV_S_HEAD_LEN);
            life_time = s_head.lifetime;
            shift += RECV_HEAD_LEN;

            unsigned_wsa.len = s_head.wsa_len;
            unsigned_wsa.buf = malloc(unsigned_wsa.len);
            if(!unsigned_wsa.buf){
                wave_malloc_error();
                goto destructor;
            }
            memcpy(unsigned_wsa.buf, shift, unsigned_wsa.len);
            shift += unsigned_wsa.len;

            permission_len = recv_data_len - RECV_HEAD_LEN - unsigned_wsa.len;

            permissions.len = 0;
            permissions.serviceinfos = malloc(sizeof(serviceinfo)*32);//分配32个为最大的长度
            while(permission_len > 0){
                memcpy(&per, shift, 4);
                shift += 4;

                memcpy(&permissions.serviceinfos[permissions.len].max_priority, &per.priority, 1);

                permissions.serviceinfos[permissions.len].psid = psidn2h(shift, per.psid_len);

                if(per.ssp_len > 0){
                    permissions.serviceinfos[permissions.len].ssp.len = per.ssp_len;
                    permissions.serviceinfos[permissions.len].ssp.buf = malloc(per.ssp_len);
                    if(!permissions.serviceinfos[permissions.len].ssp.buf){
                        wave_malloc_error();
                        goto destructor;
                    }
                    memcpy(permissions.serviceinfos[permissions.len].ssp.buf, shift, per.ssp_len);
                }
                else{
                    permissions.serviceinfos[permissions.len].ssp.len = 0;
                    permissions.serviceinfos[permissions.len].ssp.buf = NULL;
                }
                shift += per.ssp_len;
                
                if(per.pssi_len > 4){
                    wave_error_printf("lsis太长");
                    goto destructor;
                }
                permissions.serviceinfos[permissions.len].lsis = 0;
                for(i = 0; i < per.pssi_len; i++){
                    permissions.serviceinfos[permissions.len].lsis += (*shift)*256;
                    shift++;
                }
                permissions.len++;
                permission_len = permission_len - per.psid_len - per.ssp_len - per.pssi_len - 4;
            }
            ret = sec_signed_wsa(&sec_db, &unsigned_wsa, &permissions, life_time, &signed_wsa);
            memset((char*)NLMSG_DATA(nlh, 0, MAX_PAYLOAD));
            memset(sbuf, 0, MAX_PAYLOAD);
            if(ret == SUCCESS){
                s_wsa.wsa_len = signed_wsa.len;
                s_wsa.broadcast = s_head.broadcast;
                s_wsa.change_count = s_head.change_count;
                s_wsa.channel = s_head.channel;
                s_wsa.result_code = DOT2_SIGN_SUCCESS;
                memcpy(sbuf, &s_wsa, sizeof(struct signed_wsa));
                memcpy(sbuf+sizeof(struct signed_wsa), signed_wsa.buf, signed_wsa.len);

                memcpy(NLMSG_DATA(&nlh), sbuf, signed_wsa.len+sizeof(struct signed_wsa));
            }
            else{
                wave_error_printf("签名失败");
                s_wsa.wsa_len = 0;
                s_wsa.broadcast = s_head.broadcast;
                s_wsa.change_count = s_head.change_count;
                s_wsa.channel = s_head.channel;
                s_wsa.result_code = DOT2_SIGN_FAILURE;
                memcpy(sbuf, &s_wsa, sizeof(struct signed_wsa));
                memcpy(NLMSG_DATA(&nlh), sbuf, signed_wsa.len+sizeof(struct signed_wsa));
            }
            if(sendmsg(fd, &msg, 0) < 0){
                wave_error_printf("发送消息给内核失败了");
                goto destructor;
            }
        }
        //验证
        else if(*shift == 1){
            memcpy(&v_head, shift, RECV_V_HEAD_LEN);
            shift += RECV_V_HEAD_LEN;

            INIT(unverified_wsa);
            INIT(results);
            INIT(wsa_data);
            INIT(ssp_array);
            INIT(generation_time);
            INIT(expiry_time);
            INIT(location);
            INIT(last_crl_time);
            INIT(next_crl_time);
            INIT(cert);

            unverified_wsa.len = v_head.wsa_len;
            unverified_wsa.buf = malloc(v_head.wsa_len);
            if(!unverified_wsa.buf){
                wave_malloc_error();
                goto destructor;
            }
            memcpy(unverified_wsa.buf, shift, v_head.wsa_len);

            memset((char*)NLMSG_DATA(nlh, 0, MAX_PAYLOAD));
            memset(sbuf, 0, MAX_PAYLOAD);
            ret = sec_signed_data_verification(&sec_db, &unverified_wsa, &results, &ssp_array, &generation_time,
                    &expiry_time, &location, &last_crl_time, &next_crl_time, &cert);
            if(ret == SUCCESS){
                v_wsa.pid = getpid();
                memcpy(v_wsa.src_mac, v_head.src_mac, 6);
                v_wsa.rcpi = v_head.rcpi;
                v_wsa.result_code = DOT2_SUCCESS;
                v_wsa.wsa_len = wsa_data.len; 
                v_wsa.gen_time = generation_time.time;
                v_wsa.expire_time = expiry_time;
                v_wsa_.ssp_len = 0;
                v_wsa.next_crl_time_len = next_crl_time.len*sizeof(time32);

                memcpy(sbuf, &v_wsa, sizeof(struct verified_wsa));
                memcpy(sbuf+sizeof(struct verified_wsa), wsa_data.buf, wsa_data.len);

                char *ssp_shift = sbuf + sizeof(struct verified_wsa) + wsa_data.len;
                for(i = 0; i < ssp_array.len; i++){
                    if(ssp_array.ssps[i].len != 0){
                        memcpy(ssp_shift, ssp_array.ssps[i].buf, ssp_array.ssps[i].len);
                        ssp_shift += ssp_array.ssps[i].len;
                        v_wsa.ssp_len += ssp_array.ssps[i].len;
                    }
                    else{
                        *ssp_shift = '\0';
                        ssp_shift++;
                        v_wsa.ssp_len++;
                    }
                }

                memcpy(ssp_shift, next_crl_time.times, sizeof(time32)*next_crl_time.len);
                memcpy(NLMSG_DATA(&nlh), sbuf, sizeof(struct verified_wsa)+v_wsa.wsa_len+v_wsa.ssp_len+v_wsa.next_crl_time_len);
            }
            else if(ret == )
            if(sendmsg(fd, &msg, 0) < 0){
                wave_error_printf("发送消息给内核失败了");
                goto destructor;
            }
        }
        else
            wave_error_printf("不支持的dot3请求类型");
destructor:
        string_free(&unsigned_wsa);
        string_free(&signed_wsa);
        serviceinfo_array_free(&permissions);
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
