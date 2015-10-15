#include"cmp.h"
#include<pthread.h>
#include<stddef.h>
#include "../utils/common.h"
#include "../cme/cme.h"
#include "../pssme/pssme.h"
#include "../sec/sec.h"
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#define forward 60  //单位是s
#define overdue 60*10 // 单位是s
#define INIT(m) memset(&m,0,sizeof(m))
struct crl_req_time{
    struct list_head list;
    time32 time;//单位s
};
struct wsa_cert_db{
    struct list_head list;
    cmh cert_cmh;
    cmh key_pair_cmh;
};

struct cmp_db{
    struct crl_req_time crl_time;
    struct wsa_cert_db certs;
    cmh req_cert_cmh;
    cmh req_cert_enc_cmh;
    struct lsis_array req_lsises;
    cmh ca_cmh;
    certificate ca_cert;
    string identifier;
    geographic_region geographic_region;
    u32 life_time;//单位day
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
            pthread_mutex_unlock(&cmdb->lock);
            return;
        }
        first = list_entry(head->list.next,struct crl_req_time,list);
        list_del(&first->list);
        free(first);
    }while(next_time -forward < now );
    pthread_mutex_unlokc(&cmdb->lock);

    signal(SIGALRM,crl_alarm_handle);
    alarm(now - next_time + forward);
}
static void crl_alarm_handle(int signo){
    if(signo == SIGALRM){
        set_crl_request_alarm(cmdb);
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
    cmdb = (struct cmp_db*)malloc(sizeof(struct cmp_db));
    if(cmdb == NULL)
        return -1;
    cmdb->pending = 0;
    pthread_mutex_init(&cmdb->lock,NULL); 
    //这里很多都没数据没有初始化，这里先不写
    
    return 0;
}
static int generate_cert_request(struct sec_db* sdb,struct cmp_db* cmdb,cme_lsis lsis,
                            string* veri_pk,string* enc_pk,string* res_pk,
                            string* data,certid10* request_hash){
    serviceinfo_array serviceinfos;
    struct cme_permissions permissions;
    psid_priority_ssp* pps;
    int i;
    time32 expire;
    time_t now;

    INIT(serviceinfos);
    INIT(permissions);

    if(pssme_get_serviceinfo(sdb,lsis,&serviceinfos))
        goto fail;

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
                            IMPLICT,&permissions,&cmdb->identifier,&cmdb->geographic_region,
                           true,true,now,expire,veri_pk,enc_pk,res_pk,&cmdb->ca_cert,data,request_hash)){
        pthread_mutex_unlock(&cmdb->lock);
        goto fail;
    }

    lsis_array_free(&cmdb->req_lsises);
    cmdb->req_lsises.lsis = (pssme_lsis*)malloc(sizeof(pssme_lsis) * serviceinfos.len);
    if(cmdb->req_lsises.lsis == NULL){
        pthread_mutex_unlock(&cmdb->lock);
        goto fail;
    }
    cmdb->req_lsises.len = serviceinfos.len;
    for(i=0;i<serviceinfos.len;i++){
        *(cmdb->req_lsises.lsis+i) = (serviceinfos.serviceinfos + i)->lsis;
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
    string cert_pk,keypair_pk;
    cme_lsis lsis = -1;
    string data;
    certid10 resquest_hash;
    int i;
    INIT(cert_pk);
    INIT(keypair_pk);
    INIT(data);
    INIT(resquest_hash);

    if(cme_cmh_request(sdb,&cert_cmh) || cme_cmh_request(sdb,&key_pair_cmh))
        goto fail;
    if(cme_generate_keypair(sdb,cert_cmh,ECDSA_NISTP256_WITH_SHA256,&cert_pk)||
            cme_generate_keypair(sdb,key_pair_cmh,ECIES_NISTP256,&keypair_pk))
        goto fail;
    if(generate_cert_request(sdb,cmdb,lsis,&cert_pk,NULL,&keypair_pk,&data,&resquest_hash))
        goto fail;
    ca_write(data.buf,data.len);
    pthread_mutex_lock(&cmdb->lock);
    cmdb->req_cert_cmh = cert_cmh;
    cmdb->req_cert_enc_cmh  = key_pair_cmh;
    pthread_mutex_unlock(&cmdb->lock);
    
    string_free(&cert_pk);
    string_free(&keypair_pk);
    string_free(&data);
    certid10_free(&resquest_hash);
    return;

fail:
    string_free(&cert_pk);
    string_free(&keypair_pk);
    string_free(&data);
    certid10_free(&resquest_hash);
    return ;
    
}
static void crl_request_progress(struct cmp_db* cmdb){

}
static void crl_recieve_progress(struct sec_db* sdb,string* data){
    crl crl;
    tobesigned_crl* unsigned_crl;
    int i;

    INIT(crl);

    if(sec_crl_verification(sdb,data,overdue,NULL,
                NULL,NULL))
        goto fail;
    if( buf_2_crl(data->buf,data->len,&crl))
        goto fail;
    
    unsigned_crl  = &crl.unsigned_crl;
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

    crl_free(&crl);
fail:
    crl_free(&crl);
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
    if(pssme_cryptomaterial_handle_storage(sdb,cert_cmh,&cmdb->req_lsises)){
        pthread_mutex_unlock(&cmdb->lock);
        goto fail;
    }
    lsis_array_free(&cmdb->req_lsises);
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
static void data_recieve_progress(){

}
void cmp_run(struct sec_db* sdb){
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
        if(cmdb->pending & RECIEVE_DATA){
            data_recieve_progress();
            cmdb->pending &= ~RECIEVE_DATA;
        }
        pthread_mutex_unlock(&cmdb->lock);
    }
    return;
}

