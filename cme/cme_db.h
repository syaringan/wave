#ifndef CME_DB_H
#define CME_DB_H

#include "data/data.h"
#include "utils/list.h"
#include "utils/rb.h"
#include "utils/string.h"
#include "utils/lock.h"
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

enum identifier_type{
    ID_CERTIFICATE = 0,//这个有两重意义，在construct——chain中为certificate_array
    ID_HASHEDID8 = 1,
    ID_CERTID10 = 2,
};
struct cert_info_cmp{
    enum identifier_type type;
    union{
        struct certid10 certid10;
        struct hashedid8 hashedid8;
    }u;
};
void inline cme_alloced_lsis_free(struct cme_alloced_lsis* alloced_lsis);
void inline cmh_keypaired_free(struct cmh_keypaired* cmh_keys);
void inline cmh_key_cert_free(struct  cmh_key_cert* key_cert);
void inline cert_info_free(struct cert_info* certinfo);
int cme_db_2_file(struct cme_db *cdb,char *name);
int file_2_cme_db(struct cme_db *cdb,char *name);
int cme_db_init(struct cme_db *cdb);
int cme_db_empty(struct cme_db *cdb);
void cme_lsis_insert(struct cme_db* cdb,struct cme_alloced_lsis* lsis);
void cme_cmh_init_insert(struct cme_db* cdb,struct cmh_chain* cmh);
void cert_info_init_rb(struct cert_info* certinfo);
struct cert_info* cert_info_insert(struct cert_info* root,struct cert_info* node);
struct cert_info* cert_info_find(struct cert_info* root,void* value);
struct cert_info* cert_info_delete(struct cert_info* root,struct cert_info* node);
void cert_info_cpy(struct cert_info *dst,struct cert_info *src );
void ckc_init(struct cmh_key_cert* ckc);
struct cmh_key_cert* ckc_insert(struct cmh_key_cert* root,struct cmh_key_cert* node);
struct cmh_key_cert* ckc_find(struct cmh_key_cert* root,void* value);
struct cmh_key_cert* ckc_delete(struct cmh_key_cert* root,struct cmh_key_cert* node);
void cme_db_free(struct cme_db* cdb);
#endif
