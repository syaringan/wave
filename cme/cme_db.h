#ifndef CME_DB_H
#define CME_DB_H

#include "../data/data.h"
#include "../utils/list.h"
#include "../utils/rb.h"
#include "../utils/string.h"
#include "../utils/lock.h"
#include <stdio.h>
typedef s32 cme_lsis;
typedef u32 cmh;//cmh从1开始发放，不准放0
struct cmh_init{
    cmh cmh;
    struct list_head list;
};
struct cmh_keypaired{
    struct list_head list;
    cmh cmh;
    pk_algorithm algorithm;
    string public_key;
    string private_key;
};
struct cmh_key_cert{
    cmh cmh;
    struct rb_head rb;
    string private_key;
    certificate *cert;
};
struct alloced_cmhs{
   struct cmh_init cmh_init;
   struct cmh_keypaired cmh_keys;
   struct cmh_key_cert* cmh_key_cert;
};
struct cmh_chain{
    cmh cmh;
    struct list_head list;
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
struct crl_ca_id{
    struct list_head list;
    hashedid8 ca_id;
    struct crl_serial_number crl_info_list;
};
struct crl_head{
    struct list_head list;
    crl_series crl_series;
    struct crl_ca_id ca_id_list;
};
struct revocation{
    time64 expriry;
    hashedid8 ca_id;
};
struct cert_head{
  certificate *cert;
  certid10 certid10;
  bool verified;
  struct crl_head* crl;
  bool trust_anchor;
  struct rb_head rb;
  struct revocation revocation;
};
struct cme_db{
    struct cert_head certs;
    struct crl_head crls;
    struct cme_lsis_db lsises;
    struct cmh_db cmhs;
    lock lock;
};
#endif
