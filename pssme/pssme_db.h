#ifndef PSSME_DB_H
#define PSSME_DB_H
#include "utils/string.h"
#include "data/data.h"
#include "utils/list.h"
#include "utils/rb.h"
#include "utils/lock.h"
#include "utils/common.h"
#include "cme/cme_db.h"

typedef u32 pssme_lsis;
typedef u8 priority;
struct pssme_psid_priority_ssp{
    psid psid;
    priority priority;
    string ssp;
};

struct pssme_psid_priority_ssp_chain{
    struct pssme_psid_priority_ssp permission;
    struct list_head list;
};

struct pssme_alloc_lsis{
    struct list_head list;
    pssme_lsis lsis;
    struct pssme_psid_priority_ssp_chain
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
    pssme_lsis* lsis;
    u32 len;
};
struct pssme_local_cert{
    struct list_head list;
    cmh cmh;//这个是个数
    struct pssme_lsis_array lsis_array;
};
struct pssme_receive_cert{
    struct list_head list;
    certificate cert;
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
static void inline pssme_psid_priority_ssp_free(struct pssme_psid_priority_ssp* ptr){
    if(ptr == NULL)
        return;
    string_free(&ptr->ssp);
}
static void inline pssme_psid_priority_ssp_chain_free(struct pssme_psid_priority_ssp_chain* ptr){
    pssme_psid_priority_ssp_free(&ptr->permission);
}
int file_2_pdb(struct pssme_db* pdb,char *name);
int pdb_2_file(struct pssme_db* pdb,char *name);
void psme_db_init(struct pssme_db* pdb);
void pssme_db_free(struct pssme_db* pdb);


/**
 * 释放一个pssme_local_cert链表
 */
void pssme_local_cert_list_free(struct pssme_local_cert *head);
/*
 * 释放一个pssme_local_cert节点
 * */
void pssme_local_cert_free(struct pssme_local_cert *node);
#endif
