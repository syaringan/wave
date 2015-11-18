#ifndef CME_DB_H
#define CME_DB_H

#include "../data/data.h"
#include "../utils/list.h"
#include "../utils/rb.h"
#include "../utils/string.h"
#include "../utils/lock.h"
#include <stdio.h>
typedef u32 cme_lsis;//从1开始发送，不准放0
typedef u32 cmh;//cmh从1开始发放，不准放0
struct cmh_keypaired{
    struct list_head list;
    cmh cmh;
    pk_algorithm algorithm;
    string public_key_x;
    string public_key_y;
    string private_key;
};
struct cert_info{
    certificate *cert;
    certid10 certid10;
    bool verified;
//    time32 last_recieve_crl;
  //  time32 next_recieve_crl;
    bool trust_anchor;
    //bool trusted;//这个字段是干吗的？？有用嘛？？
    bool revoked;//新加字段判断是否吊销
    struct rb_head rb;
    time64 expriry;
    struct cmh_key_cert *key_cert;
  //  hashedid8 ca_id;
};
struct cmh_key_cert{
    cmh cmh;
    struct rb_head rb;
    string private_key;
    certificate *cert;
    struct cert_info* cert_info;

};
struct cmh_chain{
    cmh cmh;
    struct list_head list;
};
struct alloced_cmhs{
   struct cmh_chain cmh_init;
   struct cmh_keypaired cmh_keys;
   struct cmh_key_cert *cmh_key_cert;
};

struct cmh_db{
    struct alloced_cmhs alloc_cmhs;
    struct cmh_chain cmh_chain;
};
struct cme_lsis_chain{
    struct list_head list;
    cme_lsis lsis;
};
struct cme_alloced_lsis{
    struct list_head list;
    cme_lsis lsis;
    string data;
};
struct cme_lsis_db{
    struct cme_alloced_lsis alloced_lsis;
    struct cme_lsis_chain lsises;
};
struct crl_serial_number{
    struct list_head list;
    u32 serial_number;
    time32 start_period;
    time32 issue_date;
    time32 next_crl_time;
    crl_type type;

};
struct revoked_certs{
    struct list_head list;
    certid10 certid;
};
struct crl_ca_id{
    struct list_head list;
    hashedid8 ca_id;
    struct crl_serial_number crl_info_list;
    struct revoked_certs revoked_certs;//新增的用来存放吊销的所有证书,在调用add_certifiacte_revocation的时候更新哦。
};
struct crl_head{
    struct list_head list;
    crl_series crl_series;
    struct crl_ca_id ca_id_list;
};

struct cme_db{
    struct cert_info *certs;
    struct crl_head crls;
    struct cme_lsis_db lsises;
    struct cmh_db cmhs;
    lock lock;
};
static void inline cmh_keypaired_free(struct cmh_keypaired* cmh_keys){
    if(cmh_keys == NULL)
        return ;
    string_free(&cmh_keys->private_key);
    string_free(&cmh_keys->public_key_x);
    string_free(&cmh_keys->public_key_y);
}
static void inline cmh_key_cert_free(strcut cmh_key_cert* key_cert){
    if(key_cert == NULL)
        return ;
    certificate_free(key_cert->cert);
    key_cert->cert = NULL;
}
static void inline cert_info_free(struct cert_info* certinfo){
    if(certinfo == NULL)
        return ;
    if(certinfo->cert != NULL){
        certificate_free(certinfo->cert);
        certinfo->cert = NULL;
    }
}
#endif
