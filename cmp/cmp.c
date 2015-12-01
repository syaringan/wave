/*************
 *作者：大力
 */
#include"cmp.h"
#include<pthread.h>
#include<stddef.h>
#include "../utils/common.h"
#include "../cme/cme.h"
#include "../pssme/pssme.h"
#include "../sec/sec.h"
#include "../utils/debug.h"
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include "../data/data_handle.h"
#define FORWARD 60  //单位是s
#define OVERDUE 60*10 // 单位是s
#define NETWORK_DELAY 60*2 // 单位是s
#define CRL_REQUSET_LEN 100 //单位字节
#define RECIEVE_DATA_MAXLEN 1000
#define TO_FILE_LEN 100
#define INIT(m) memset(&m,0,sizeof(m))
#define CERTIFICATE_BUF_LEN 1024
struct crl_req_time{
    struct list_head list;
    time32 time;//单位s
    hashedid8 issuer;
    crl_series crl_series;
    time32 issue_date;
};

struct cmp_db{
    struct crl_req_time crl_time;
    time32 crl_request_issue_date;
    hashedid8 crl_request_issuer;
    crl_series crl_request_crl_series;
    
    cmh req_cert_cmh;
    cmh req_cert_enc_cmh;
    struct pssme_lsis_array req_cert_lsises;

    string identifier;
    geographic_region region;
    u32 life_time;//单位day
    
    cmh ca_cmh;
    certificate ca_cert;

    u32 pending;
    pthread_mutex_t lock;
};

enum pending_flags{
    CRL_REQUEST = 1<<0,
    CERTFICATE_REQUEST = 1<<1,
    RECIEVE_DATA = 1<<2,
};

pthread_cond_t pending_cond = PTHREAD_COND_INITIALIZER;
struct cmp_db* cmdb = NULL;

static int cert_2_file(struct cmp_db* cmdb,FILE* fd){
    char *buf=NULL;
    int cert_len;
    if(fwrite(&cmdb->ca_cmh,sizeof(cmdb->ca_cmh),1,fd) != 1){
        wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
        return -1;
    }

    buf = (char*)malloc(CERTIFICATE_BUF_LEN);
    if(buf == NULL){
        wave_malloc_error();
        return -1;
    }

    cert_len = certificate_2_buf(&cmdb->ca_cert,buf,CERTIFICATE_BUF_LEN);
    if(cert_len <=0){
        free(buf);
        return -1;
    }
    if(fwrite(buf,1,cert_len,fd) != cert_len){
        free(buf);
        wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
        return -1;
    }
    free(buf);
    return 0;
}
static int others_2_file(struct cmp_db* cmdb,FILE* fd){
    
    if(fwrite(&cmdb->identifier.len,sizeof(cmdb->identifier.len),1,fd) != 1||
            fwrite(cmdb->identifier.buf,1,cmdb->identifier.len,fd) != cmdb->identifier.len){
        wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    if( fwrite(&cmdb->region.region_type,sizeof(cmdb->region.region_type),1,fd) != 1){
         wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    switch(cmdb->region.region_type){
        case FROM_ISSUER:
            break;
        case CIRCLE:
            if( fwrite(&cmdb->region.u.circular_region,sizeof(cmdb->region.u.circular_region),1,fd) != 1){
                wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
                return -1;
            }
            break;
        case RECTANGLE:
            if( fwrite(&cmdb->region.u.rectangular_region.len,sizeof(cmdb->region.u.rectangular_region.len),1,fd) != 1||
                    fwrite(cmdb->region.u.rectangular_region.buf,sizeof(*cmdb->region.u.rectangular_region.buf),
                                cmdb->region.u.rectangular_region.len,fd) != cmdb->region.u.rectangular_region.len){
                wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
                return -1;
            }
            break;
        case POLYGON:
            if( fwrite(&cmdb->region.u.polygonal_region.len,sizeof(cmdb->region.u.polygonal_region.len),1,fd) != 1||
                    fwrite(cmdb->region.u.polygonal_region.buf,sizeof(*cmdb->region.u.polygonal_region.buf),
                                cmdb->region.u.polygonal_region.len,fd) != cmdb->region.u.polygonal_region.len){
                wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
                return -1;      
            }
            break;
        case NONE:
            if( fwrite(&cmdb->region.u.other_region.len,sizeof(cmdb->region.u.other_region.len),1,fd) != 1||
                    fwrite(cmdb->region.u.other_region.buf,sizeof(*cmdb->region.u.other_region.buf),
                                cmdb->region.u.other_region.len,fd) != cmdb->region.u.other_region.len){
                wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
                return -1;
            }
            break;
        default:
            return -1;
    }

    if(fwrite(&cmdb->life_time,sizeof(cmdb->life_time),1,fd)!=1){
        wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
        return -1;
    } 
    return 0;
}

static int lsis_array_2_file(struct cmp_db* cmdb,FILE* fd){
    if(fwrite(&cmdb->req_cert_lsises.len,sizeof(cmdb->req_cert_lsises.len),1,fd) != 1||
            fwrite(cmdb->req_cert_lsises.lsis,sizeof(*cmdb->req_cert_lsises.lsis),cmdb->req_cert_lsises.len,fd) !=
                            cmdb->req_cert_lsises.len){
        wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int crl_cert_request_2_file(struct cmp_db* cmdb,FILE *fd){
    if(fwrite(&cmdb->crl_request_issue_date,sizeof(cmdb->crl_request_issue_date),1,fd) != 1 ||
            fwrite(&cmdb->crl_request_issuer,sizeof(cmdb->crl_request_issuer),1,fd) != 1||
            fwrite(&cmdb->crl_request_crl_series,sizeof(cmdb->crl_request_crl_series),1,fd) != 1||
            fwrite(&cmdb->req_cert_cmh,sizeof(cmdb->req_cert_cmh),1,fd) != 1||
            fwrite(&cmdb->req_cert_enc_cmh,sizeof(cmdb->req_cert_enc_cmh),1,fd) != 1){
        wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0; 
}
static int crl_req_time_2_file(struct crl_req_time* ptr,FILE* fd){
    if( fwrite(&ptr->time,sizeof(ptr->time),1,fd) != 1||
            fwrite(&ptr->issuer,sizeof(ptr->issuer),1,fd) != 1 ||
            fwrite(&ptr->crl_series,sizeof(ptr->crl_series),1,fd) != 1||
            fwrite(&ptr->issue_date,sizeof(ptr->issue_date),1,fd) != 1){
        wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int crl_req_time_list_2_file(struct cmp_db* cmdb,FILE* fd){
    struct list_head *head;
    struct crl_req_time* ptr;
    int len = 0; 
    head = &cmdb->crl_time.list;
    list_for_each_entry(ptr,head,list)
        len++;
    if( fwrite(&len,sizeof(len),1,fd) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    list_for_each_entry(ptr,head,list){
        if( ( crl_req_time_2_file(ptr,fd)) < 0){
            return -1;
        }
    }
    return 0;
}
static void cmp_db_2_file(struct cmp_db* cmdb,const char* name){
    FILE *fd;
    if (( fd = fopen(name,"w") )  == NULL ){
        wave_printf(MSG_ERROR,"打开文件 %s 失败",name);
        return ;
    } 
    if ( crl_req_time_list_2_file(cmdb,fd) <0)
        goto fail;
    if ( crl_cert_request_2_file(cmdb,fd) < 0)
        goto fail;
    if( lsis_array_2_file(cmdb,fd) < 0)
        goto fail;
    if( others_2_file(cmdb,fd) < 0)
        goto fail;
    if( cert_2_file(cmdb,fd) < 0)
        goto fail;
    fclose(fd);
fail:
    fclose(fd);
}


static int file_2_ca_cert(struct cmp_db* cmdb,FILE* fd){
    char* buf=NULL;
    int readlen,len;
    if( fread(&cmdb->ca_cmh,sizeof(cmdb->ca_cmh),1,fd) != 1){
        wave_error_printf("read文件失败 %s %d",__FILE__,__LINE__);
        return -1;
    }
    buf = (char*)malloc(CERTIFICATE_BUF_LEN);
    if(buf == NULL){
        wave_malloc_error();
        return -1;
    }
    readlen = fread(buf,1,CERTIFICATE_BUF_LEN,fd);
    if( readlen <=0){
        wave_error_printf("读取文件失败 %s %d",__FILE__,__LINE__);
        free(buf);
        return -1;
    }
    len = buf_2_certificate(buf,readlen,&cmdb->ca_cert);
    if(len <=0){
        free(buf);
        return -1;
    }
    fseek(fd,len-readlen,SEEK_CUR);
    free(buf);
    return 0;
}
static int file_2_others(struct cmp_db* cmdb,FILE* fd){
    if(fread(&cmdb->identifier.len,sizeof(cmdb->identifier.len),1,fd) != 1){
        wave_error_printf("read文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    cmdb->identifier.buf = (u8*)malloc(cmdb->identifier.len);
    if(cmdb->identifier.buf == NULL){
        wave_malloc_error();
        return -1;
    }
    if( fread(cmdb->identifier.buf,1,cmdb->identifier.len,fd) != cmdb->identifier.len){
        wave_error_printf("read文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    if( fread(&cmdb->region.region_type,sizeof(cmdb->region.region_type),1,fd) != 1){
         wave_error_printf("read文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    switch(cmdb->region.region_type){
        case FROM_ISSUER:
            break;
        case CIRCLE:
            if( fread(&cmdb->region.u.circular_region,sizeof(cmdb->region.u.circular_region),1,fd) != 1){
                wave_error_printf("read文件失败 %s %d",__FILE__,__LINE__);
                return -1;
            }
            break;
        case RECTANGLE:
            if( fread(&cmdb->region.u.rectangular_region.len,sizeof(cmdb->region.u.rectangular_region.len),1,fd) != 1){
                wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
                return -1;
            }
            cmdb->region.u.rectangular_region.buf = (rectangular_region*)malloc(sizeof(rectangular_region) * cmdb->region.u.rectangular_region.len);
            if(cmdb->region.u.rectangular_region.buf == NULL){
                wave_malloc_error();
                return -1;
            }
            if( fread(cmdb->region.u.rectangular_region.buf,sizeof(*cmdb->region.u.rectangular_region.buf),
                        cmdb->region.u.rectangular_region.len,fd) != cmdb->region.u.rectangular_region.len){
                wave_error_printf("read 文件有问题 %s  %d",__FILE__,__LINE__);
                return -1;
            }
            break;
        case POLYGON:
            if( fread(&cmdb->region.u.polygonal_region.len,sizeof(cmdb->region.u.polygonal_region.len),1,fd) != 1){
                wave_error_printf("写入文件失败 %s %d",__FILE__,__LINE__);
                return -1;
            }
            cmdb->region.u.polygonal_region.buf = (two_d_location*)malloc(sizeof(two_d_location) * cmdb->region.u.polygonal_region.len);
            if(cmdb->region.u.polygonal_region.buf == NULL){
                wave_malloc_error();
                return -1;
            }
            if( fread(cmdb->region.u.polygonal_region.buf,sizeof(*cmdb->region.u.polygonal_region.buf),
                        cmdb->region.u.polygonal_region.len,fd) != cmdb->region.u.polygonal_region.len){
                wave_error_printf("read 文件有问题 %s  %d",__FILE__,__LINE__);
                return -1;
            }
            break;
        case NONE:
            if( fread(&cmdb->region.u.other_region.len,sizeof(cmdb->region.u.other_region.len),1,fd) != 1){
                wave_error_printf("read文件失败 %s %d",__FILE__,__LINE__);
                return -1;
            }
            cmdb->region.u.other_region.buf = (u8*)malloc(cmdb->region.u.other_region.len);
            if(cmdb->region.u.other_region.buf == NULL){
                wave_malloc_error();
                return -1;
            }
            if( fread(cmdb->region.u.other_region.buf,1,cmdb->region.u.other_region.len,fd) != cmdb->region.u.other_region.len){
                wave_error_printf("read  文件有问题 %s %d",__FILE__,__LINE__);
                return -1;
            }
            break;
        default:
            return -1;
    }
    if(fread(&cmdb->life_time,sizeof(cmdb->life_time),1,fd)!=1){
        wave_error_printf("read文件失败 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
static int file_2_lsis_array(struct cmp_db* cmdb,FILE* fd){
    if( fread(&cmdb->req_cert_lsises.len,sizeof(cmdb->req_cert_lsises.len),1,fd) != 1){
        wave_error_printf("read文件有问题 %s %d",__FILE__,__LINE__);
        return -1;
    }
    cmdb->req_cert_lsises.lsis = (pssme_lsis*)malloc(sizeof(pssme_lsis)*cmdb->req_cert_lsises.len);
    if(cmdb->req_cert_lsises.lsis == NULL){
        wave_malloc_error();
        return -1;
    }
    if( fread(cmdb->req_cert_lsises.lsis,sizeof(pssme_lsis),cmdb->req_cert_lsises.len,fd) != 
                cmdb->req_cert_lsises.len){
        wave_error_printf("read 文件有问题,%s %d",__FILE__,__LINE__);
    }
    return 0;
}
static int file_2_crl_cert(struct cmp_db* cmdb,FILE* fd){
    if(fread(&cmdb->crl_request_issue_date,sizeof(cmdb->crl_request_issue_date),1,fd) != 1 ||
            fread(&cmdb->crl_request_issuer,sizeof(cmdb->crl_request_issuer),1,fd) != 1||
            fread(&cmdb->crl_request_crl_series,sizeof(cmdb->crl_request_crl_series),1,fd) != 1||
            fread(&cmdb->req_cert_cmh,sizeof(cmdb->req_cert_cmh),1,fd) != 1||
            fread(&cmdb->req_cert_enc_cmh,sizeof(cmdb->req_cert_enc_cmh),1,fd) != 1){
        wave_error_printf("read文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0; 
}
static int file_2_crl_req_time(struct crl_req_time* ptr,FILE* fd){
    if( fread(&ptr->time,sizeof(ptr->time),1,fd) != 1||
            fread(&ptr->issuer,sizeof(ptr->issuer),1,fd) != 1 ||
            fread(&ptr->crl_series,sizeof(ptr->crl_series),1,fd) != 1||
            fread(&ptr->issue_date,sizeof(ptr->issue_date),1,fd) != 1){
        wave_error_printf("写入文件有错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}

static int file_2_crl_req_time_list(struct cmp_db* cmdb,FILE* fd){
    int len,i;
    struct list_head *head;
    struct crl_req_time* ptr;
    
    head = &cmdb->crl_time.list;
    if( fwrite(&len,sizeof(len),1,fd) != 1){
        wave_error_printf("写入文件错误 %s %d",__FILE__,__LINE__);
        return -1;
    }
    for(i=0;i<len;i++){
        ptr = (struct crl_req_time*)malloc(sizeof(struct crl_req_time));
        if(ptr == NULL){
            wave_malloc_error();
            return -1;
        }
        if(file_2_crl_req_time(ptr,fd)){
            free(ptr);
            return -1;
        }
        list_add_tail(&ptr->list,head);

    }
    return 0;
}
static int file_2_cmp_db(struct cmp_db* cmdb,const char* name){
    FILE* fd;
    if( (fd = fopen(name,"r"))  == NULL){
        wave_error_printf("文件 %s 打开失败\n",name);
        fclose(fd);
        return -2;
    }
    if( file_2_crl_req_time_list(cmdb,fd) ||
            file_2_crl_cert(cmdb,fd) ||
            file_2_lsis_array(cmdb,fd) ||
            file_2_others(cmdb,fd) ||
            file_2_ca_cert(cmdb,fd)){
        fclose(fd);
        return -1;
    }
    fclose(fd);
    return 0;
}

static void crl_req_time_insert(struct cmp_db* cmdb,struct crl_req_time* new){
    struct crl_req_time *head,*ptr;
    pthread_mutex_lock(&cmdb->lock);
    head = &cmdb->crl_time;    
    //插入,按照时间排序
    list_for_each_entry(ptr,&head->list,list){
        if(ptr->time > new->time){
            break;
        }
    }
    list_add_tail(&new->list,&ptr->list);
    pthread_mutex_unlock(&cmdb->lock);
}

static void pending_crl_request(struct cmp_db* cmdb){
    pthread_mutex_lock(&cmdb->lock);
    cmdb->pending |= CRL_REQUEST;
    pthread_mutex_unlcok(&cmdb->lock);

    pthread_cond_signal(&pending_cond);
}
static void crl_alarm_handle(int signo);
static void set_crl_request_alarm(struct cmp_db* cmdb){
    time_t now,diff;
    time32 next_time;
    struct crl_req_time *head,*first;
    time(&now);
    pthread_mutex_lock(&cmdb->lock);
    head = &cmdb->crl_time;
    do{
        if(list_empty(&head->list)){
            wave_printf(MSG_WARNING,"cmp的crl_request链表为空");
            pthread_mutex_unlock(&cmdb->lock);
            return;
        }
        first = list_entry(head->list.next,struct crl_req_time,list);
        next_time = first->time;
        list_del(&first->list);
        if(next_time - FORWARD < now){
            wave_printf(MSG_WARNING,"cmp的crl_request链表第一个请求时间小于现在时间 请求时间为:%d "
                    "下次请求时间：%d",first->time,first->time + first->crl_series);
            first->time += first->crl_series;
            crl_req_time_insert(cmdb,first);
        }
        else{
            cmdb->crl_request_crl_series = first->crl_series;
            hashedid8_cpy(&cmdb->crl_request_issuer,&first->issuer);
            cmdb->crl_request_issue_date = first->issue_date;
            wave_printf(MSG_INFO,"插入一个crl_request  crl_series:%d issuer:HASHEDID8_FORMAT "
                    "issue data:%d",first->crl_series,HASHEDID8_VALUE(first->issuer),first->issue_date);
            free(first);
        }
    }while(next_time -FORWARD < now );
    pthread_mutex_unlock(&cmdb->lock);

    signal(SIGALRM,crl_alarm_handle);
    alarm(now - next_time + FORWARD);
}
static void crl_alarm_handle(int signo){
    if(signo == SIGALRM){
        pending_crl_request(cmdb);
    }
}
 
static void pending_certificate_request(struct cmp_db* cmdb){
    pthread_mutex_lock(&cmdb->lock);
    cmdb->pending |= CERTFICATE_REQUEST;
    pthread_mutex_unlock(&cmdb->lock);

    pthread_cond_signal(&pending_cond);
}
static void pending_recieve_data(struct cmp_db* cmdb){
    pthread_mutex_lock(&cmdb->lock);
    cmdb->pending |= RECIEVE_DATA;
    pthread_mutex_unlcok(&cmdb->lock);

    pthread_cond_signal(&pending_cond);
}
void cmp_do_certificate_applycation(){
    pending_certificate_request(cmdb);
}
void cmp_do_recieve_data(){
    pending_recieve_data(cmdb);
}

u32 cmp_init(){
    int res;
    cmdb = (struct cmp_db*)malloc(sizeof(struct cmp_db));
    if(cmdb == NULL)
        return -1;
    INIT(cmdb);
    cmdb->pending = 0;
    pthread_mutex_init(&cmdb->lock,NULL);
    INIT_LIST_HEAD(&cmdb->crl_time.list);

    res = file_2_cmp_db(cmdb,"./cmp_db.txt");
    if( res ){
        return file_2_cmp_db(cmdb,"./cmp_db.init");
    }
    return res;
}
void cmp_end(){
    cmp_db_2_file(cmdb,"./cmp_db.txt");
}
static int generate_cert_request(struct sec_db* sdb,struct cmp_db* cmdb,cme_lsis lsis,
                            public_key* veri_pk,public_key* enc_pk,public_key* res_pk,
                            string* data,certid10* request_hash){
    serviceinfo_array serviceinfos;
    struct cme_permissions permissions;
    psid_priority_ssp* pps;
    int i;
    time32 expire;
    time_t now;

    INIT(serviceinfos);
    INIT(permissions);

    if(pssme_get_serviceinfo(sdb,lsis,&serviceinfos)){
        wave_printf(MSG_ERROR,"pssme get serviceinfo 失败");
        goto fail;
    }

    permissions.type = PSID_PRIORITY_SSP;
    permissions.u.psid_priority_ssp_array.buf =
        (struct psid_priority_ssp*)malloc(sizeof(struct psid_priority_ssp) * serviceinfos.len);
    permissions.u.psid_priority_ssp_array.len = serviceinfos.len;
    pps = permissions.u.psid_priority_ssp_array.buf;

    if(pps == NULL)
        goto fail;
    for(i=0;i<serviceinfos.len;i++){
        (pps +i)->psid =
            (serviceinfos.serviceinfos + i)->psid;
        (pps +i)->max_priority = 
            (serviceinfos.serviceinfos + i)->max_priority;

        (pps+i)->service_specific_permissions.len = 
            (serviceinfos.serviceinfos + i)->ssp.len;
        (pps +i)->service_specific_permissions.buf = 
            (u8*)malloc( (serviceinfos.serviceinfos+i)->ssp.len) ;
        if((pps + i)->service_specific_permissions.buf == NULL)
            goto fail;

        memcpy( (pps +i)->service_specific_permissions.buf,
                (serviceinfos.serviceinfos+i)->ssp.buf,(serviceinfos.serviceinfos+i)->ssp.len);
    }
    
    time(&now);
    pthread_mutex_lock(&cmdb->lock);
    expire  = now + cmdb->life_time*24*60*60;
    if(sec_get_certificate_request(sdb,CERTIFICATE,cmdb->ca_cmh,WSA,
                            IMPLICT,&permissions,&cmdb->identifier,&cmdb->region,
                           true,true,now,expire,veri_pk,enc_pk,res_pk,&cmdb->ca_cert,data,request_hash)){
        pthread_mutex_unlock(&cmdb->lock);
        wave_printf(MSG_ERROR,"cmp 获取证书请求失败 %s %d",__FILE__,__LINE__);
        goto fail;
    }

    lsis_array_free(&cmdb->req_cert_lsises);
    cmdb->req_cert_lsises.lsis = (pssme_lsis*)malloc(sizeof(pssme_lsis) * serviceinfos.len);
    if(cmdb->req_cert_lsises.lsis == NULL){
        pthread_mutex_unlock(&cmdb->lock);
        goto fail;
    }
    cmdb->req_cert_lsises.len = serviceinfos.len;
    for(i=0;i<serviceinfos.len;i++){
        *(cmdb->req_cert_lsises.lsis+i) = (serviceinfos.serviceinfos + i)->lsis;
    }
    pthread_mutex_lock(&cmdb->lock);
    cme_permissions_free(&permissions);
    serviceinfo_array_free(&serviceinfos);
    return 0;
fail:
    cme_permissions_free(&permissions);
    serviceinfo_array_free(&serviceinfos);
    return -1;
}
//现在这个函数的处理逻辑是我只负责申请所有服务的一个证书，用来签证书，当信道拥挤的情况没有考虑。
static void certificate_request_progress(struct cmp_db* cmdb,struct sec_db* sdb){
    cmh cert_cmh,key_pair_cmh;
    public_key cert_pk,keypair_pk;
    string cert_pk_x,cert_pk_y,keypair_pk_x,keypair_pk_y;
    cme_lsis lsis = -1;
    string data;
    certid10 resquest_hash;
    int i;

    INIT(cert_pk);
    INIT(cert_pk_x);
    INIT(cert_pk_y);
    INIT(keypair_pk);
    INIT(keypair_pk_x);
    INIT(keypair_pk_y);
    INIT(data);
    INIT(resquest_hash);

    if(cme_cmh_request(sdb,&cert_cmh) || cme_cmh_request(sdb,&key_pair_cmh))
        goto end;
    if(cme_generate_keypair(sdb,cert_cmh,ECDSA_NISTP256_WITH_SHA256,&cert_pk_x,&cert_pk_y)||
            cme_generate_keypair(sdb,key_pair_cmh,ECIES_NISTP256,&keypair_pk_x,&keypair_pk_y))
        goto end;

    cert_pk.algorithm = ECDSA_NISTP256_WITH_SHA256;
    cert_pk.u.public_key.type = UNCOMPRESSED;
    cert_pk.u.public_key.x.len = cert_pk_x.len;
    if(cert_pk.u.public_key.x.buf = (u8*)malloc(cert_pk_x.len)){
        wave_malloc_error();
        goto end;
    }
    memcpy(cert_pk.u.public_key.x.buf,cert_pk_x.buf,cert_pk_x.len);
    cert_pk.u.public_key.u.y.len = cert_pk_y.len;
    if(cert_pk.u.public_key.u.y.buf = (u8*)malloc(cert_pk_y.len)){
        wave_malloc_error();
        goto end;
    }
    memcpy(cert_pk.u.public_key.u.y.buf,cert_pk_y.buf,cert_pk_y.len);
   
    keypair_pk.algorithm = ECIES_NISTP256;
    keypair_pk.u.public_key.type = UNCOMPRESSED;
    keypair_pk.u.public_key.x.len = keypair_pk_x.len;
    if(keypair_pk.u.public_key.x.buf = (u8*)malloc(keypair_pk_x.len)){
        wave_malloc_error();
        goto end;
    }
    memcpy(keypair_pk.u.public_key.x.buf,keypair_pk_x.buf,keypair_pk_x.len);
    keypair_pk.u.public_key.u.y.len = keypair_pk_y.len;
    if(keypair_pk.u.public_key.u.y.buf = (u8*)malloc(keypair_pk_y.len)){
        wave_malloc_error();
        goto end;
    }
    memcpy(keypair_pk.u.public_key.u.y.buf,keypair_pk_y.buf,keypair_pk_y.len);
   
    if(generate_cert_request(sdb,cmdb,lsis,&cert_pk,NULL,&keypair_pk,&data,&resquest_hash))
        goto end;
    pthread_mutex_lock(&cmdb->lock);
    ca_write(&data);
    cmdb->req_cert_cmh = cert_cmh;
    cmdb->req_cert_enc_cmh  = key_pair_cmh;
    pthread_mutex_unlock(&cmdb->lock);
    
end:
    string_free(&cert_pk_x);
    string_free(&cert_pk_y);
    string_free(&keypair_pk_x);
    string_free(&keypair_pk_y);
    string_free(&data);
    public_key_free(&cert_pk);
    public_key_free(&keypair_pk);
    certid10_free(&resquest_hash);
    return ;
    
}
static void crl_request_progress(struct cmp_db* cmdb){
    sec_data sdata;
    crl_request* crl_req;
    string buf;
    u32 data_len;

    INIT(sdata);
    INIT(buf);
    
    sdata.protocol_version = CURRETN_VERSION;
    sdata.type = CRL_REQUEST;
    crl_req = &sdata.u.crl_request;
    pthread_mutex_lock(&cmdb->lock);
    crl_req->crl_series = cmdb->crl_request_crl_series;
    crl_req->issue_date = cmdb->crl_request_issue_date;
    hashedid8_cpy(&crl_req->issuer,&cmdb->crl_request_issuer);
    pthread_mutex_unlock(&cmdb->lock);

    if(sec_data_2_string(&sdata,&buf)){
        goto end;
    }
    ca_write(&buf);
    goto end;
end:
    sec_data_free(&sdata); 
    string_free(&buf);
    set_crl_request_alarm(cmdb);//发送了就设定下一个闹钟来请求
}
static void crl_recieve_progress(struct sec_db* sdb,struct cmp_db* cmdb,string* data){
    sec_data sdata;
    tobesigned_crl* unsigned_crl;
    struct crl_req_time *head,*ptr,*new;
    int i;

    INIT(sdata);

    if(sec_crl_verification(sdb,data,OVERDUE,NULL,
                NULL,NULL))
        goto fail;
    if( buf_2_sec_data(data->buf,data->len,&sdata))
        goto fail;
    
    unsigned_crl  = &sdata.u.crl.unsigned_crl;

    pthread_mutex_lock(&cmdb->lock);
    head = &cmdb->crl_time;
    list_for_each_entry(ptr,&head->list,list){
        if(ptr->crl_series == unsigned_crl->crl_series && 
                hashedid8_compare(&ptr->issuer,&unsigned_crl->ca_id) == 0)
            break;
    }
    if(&ptr->list == &head->list){
        new = (struct crl_req_time*)malloc(sizeof(struct crl_req_time));
        if(ptr == NULL)
            goto fail;
        new->crl_series = unsigned_crl->crl_series;
        new->time = unsigned_crl->next_crl;
        new->issue_date = unsigned_crl->issue_date;
        hashedid8_cpy(&new->issuer,&unsigned_crl->ca_id);
        crl_req_time_insert(cmdb,new); 
    }
    else{
        ptr->issue_date = unsigned_crl->issue_date;
        ptr->time = unsigned_crl->next_crl;
    }
    pthread_mutex_unlock(&cmdb->lock);

    if(unsigned_crl->type == ID_ONLY){
        for(i=0;i<unsigned_crl->u.entries.len;i++){
            cme_add_certificate_revocation(sdb,unsigned_crl->u.entries.buf + i,
                    &unsigned_crl->ca_id,unsigned_crl->crl_series,0);
        }
    }
    else if(unsigned_crl->type == ID_AND_EXPIRY){
        for(i=0;i<unsigned_crl->u.expiring_entries.len;i++){
            cme_add_certificate_revocation(sdb,
                    &( (unsigned_crl->u.expiring_entries.buf+i)->id),
                    &unsigned_crl->ca_id,unsigned_crl->crl_serial,
                     (unsigned_crl->u.expiring_entries.buf+i)->expiry);
        }
    }
    cme_add_crlinfo(sdb,unsigned_crl->type,unsigned_crl->crl_series,
                &unsigned_crl->ca_id,unsigned_crl->crl_serial,
                unsigned_crl->start_period,
                unsigned_crl->issue_date,
                unsigned_crl->next_crl);

    sec_data_free(&sdata);
fail:
    sec_data_free(&sdata);
}
static void cert_responce_recieve_progress(struct sec_db* sdb,struct cmp_db* cmdb,string* data){
    cmh cert_cmh,respon_cmh;
    content_type type;
    certificate certificate;
    string rec_value;
    bool ack_request;

    INIT(certificate);
    INIT(rec_value);

    pthread_mutex_lock(&cmdb->lock);
    respon_cmh = cmdb->req_cert_enc_cmh;
    cert_cmh = cmdb->req_cert_cmh;
    pthread_mutex_unlock(&cmdb->lock);
    if(cert_cmh == 0 || respon_cmh == 0)
        goto fail;
    if( sec_certificate_response_processing(sdb,respon_cmh,data,
            &type,NULL,NULL,&certificate,&rec_value,NULL) )
        goto fail;
    if(type != CERTIFICATE_RESPONSE)
        goto fail;
    /**
     * 这里设计到协议的transfor，这里我更本不知道是怎么做变换，所以我就假设它是不变的，
     * 就是rec_value.
     */
    if(cme_store_cert(sdb,cert_cmh,&certificate,&rec_value))
        goto fail;
    pthread_mutex_lock(&cmdb->lock);
    if(pssme_cryptomaterial_handle_storage(sdb,cert_cmh,&cmdb->req_cert_lsises)){
        pthread_mutex_unlock(&cmdb->lock);
        goto fail;
    }
    lsis_array_free(&cmdb->req_cert_lsises);
    cmdb->req_cert_cmh = 0;
    cmdb->req_cert_enc_cmh = 0;
    pthread_mutex_unlock(&cmdb->lock);

    certificate_free(&certificate);
    string_free(&rec_value);
    return ;

fail:
    certificate_free(&certificate);
    string_free(&rec_value);
    return ;
}
static void data_recieve_progress(struct sec_db* sdb,string* rec_data){
    sec_data sdata;
    cmh cmh;
    INIT(sdata);
    
    
    sec_data_free(&sdata);
    if(string_2_sec_data(rec_data,&sdata)){
            goto end;
    }
    if(sdata.protocol_version != CURRETN_VERSION)
            goto end;
        
    /**这个地方的逻辑不知道有没有出错，这里按照协议一共三种情况
     * 1.1602dotdata的type 是encrtypted，tobeencrypted里面的type是certificate_response
     * 2.1602dotdata的type 是encrtypted，tobeencryptted里面的type是crl。
     * 3.1602dotdata的type是crl
     *
     * 可以看到情况考虑完，应该是上述三种情况分流出来 受到的数据是crl还是certificate_response
     * 但是读协议d4，我感觉第二中情况不是我这里处理的，或者我根本没有办法处理，因为我这里不会存储那个加密的钥匙或者证书
     */
     switch(sdata.type){
            case ENCRYPTED:
            //certificate_response
                pthread_mutex_lock(&cmdb->lock);
                cmh = cmdb->req_cert_enc_cmh;
                pthread_mutex_unlock(&cmdb->lock);    
                if(!sec_secure_data_content_extration(sdb,rec_data,cmh,
                        NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)){
                    cert_responce_recieve_progress(sdb,cmdb,rec_data);
                }
                break;
            case CRL:
                crl_recieve_progress(sdb,cmdb,rec_data);
                break;
    }
end:
    sec_data_free(&sdata);
}
void cmp_do_crl_req(crl_series crl_series,hashedid8* issuer){
    struct crl_req_time *node;
    struct list_head *head;
    time_t now;
    time(&now);
    pthread_mutex_lock(&cmdb->lock);
    head = &cmdb->crl_time.list;
    list_for_each_entry(node,head,list){
        if(node->crl_series == crl_series){
            break;
        }
    }
    if(&node->list == head){
        node = (struct crl_req_time*)malloc(sizeof(struct crl_req_time));
        if(node == NULL){
            wave_error_printf("内存分配失败");
            pthread_mutex_unlock(&cmdb->lock);
            return ;
        }
        node->crl_series = crl_series;
        node->issue_date = 0;//代表要最近的
        node->time = now + 60;//加一分钟的偏移量
        hashedid8_cpy(&node->issuer,issuer);
        crl_req_time_insert(cmdb,node);
        pending_crl_request(cmdb);
    }
    pthread_mutex_unlock(&cmdb->lock);
}
//一个一直等待手数据的线程
void* read_progress(void* value){
    struct sec_db* sdb;
    string rec_data;

    INIT(rec_data);
    sdb = (struct sec_db*)value;
    while(1){
        string_free(&rec_data);
        ca_read(&rec_data);
        data_recieve_progress(sdb,&rec_data);
    }
    string_free(&rec_data);
    return 0;
}
int cmp_run(struct sec_db* sdb){
    pthread_t read_pthread;
    if(ca_init())
        return -1;
    if(cmp_init())
        return -1;
    pthread_create(&read_pthread,NULL,read_progress,sdb);//这个地方默认都可以，毕竟这个线程是不会停止，所以不用让他有分离状态
    while(1){
        pthread_mutex_lock(&cmdb->lock);
        while(cmdb->pending == 0)
            pthread_cond_wait(&pending_cond,&cmdb->lock);

        if(cmdb->pending & CRL_REQUEST ){
            crl_request_progress(cmdb);
            cmdb->pending &= ~CRL_REQUEST;
        }
        if(cmdb->pending & CERTFICATE_REQUEST){
            certificate_request_progress(cmdb,sdb);
            cmdb->pending &= ~CERTFICATE_REQUEST;
        }
        pthread_mutex_unlock(&cmdb->lock);
    }
    return 0;
}

