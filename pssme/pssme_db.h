#ifndef PSSME_DB_H
#define PSSME_DB_H
#include "../utils/string.h"
#include "../data/data.h"
#include "../utils/list.h"
#include "../utils/rb.h"
#include "../utils/lock.h"
typedef u32 pssme_lsis;
typedef u8 priority;
struct pssme_psid_priority_ssp{
    string psid;
    priority priority;
    string ssp;
};
struct pssme_psid_priority_ssp_array{
    struct pssme_psid_priority_ssp permission;
    struct list_head list;
};
struct pssme_alloc_lsis{
    struct list_head list;
    pssme_lsis lsis;
    struct pssme_psid_priority_ssp_array
            permissions;
};
struct pssme_lsis_chain{
    pssme_lsis lsis;
    struct list_head list;
};
struct pssme_lsis_db{
    struct pssme_alloc_lsis alloc_lsis;
    struct pssme_lsis_chain lsises;
};
struct pssme_lsis_array{
    struct list_head list;
    pssme_lsis lsis;
};
struct pssme_local_cert{
    struct list_head list;
    certificate certificate;
    struct pssme_lsis_array lsis_array;
};
struct pssme_receive_cert{
    struct rb_head rb_head;//根据证书里面什么？？比较
    certificate certificate;
    u64 recent_time;//最新受到的这个证书的数据的时间
};
struct pssme_cert_db{
    struct pssme_local_cert local_cert;
    struct pssme_receive_cert receive_cert;
};
struct pssme_db{
    struct pssme_cert_db cert_db;
    struct pssme_lsis_db lsis_db;
    lock lock;
};
#endif
