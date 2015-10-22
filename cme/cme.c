#include "cme.h"
#include "../data/data_handle.h"
#include"../sec/sec.h"
#include <stdlib.h>
#define INIT(n) memset(&n,0,sizeof(n))

void cme_permissions_free(struct cme_permissions* permissions){
    switch(permissions->type){
        case PSID:
            array_free(&permissions->u.psid_array);
            break;
        case PSID_PRIORITY:
            array_free(&permissions->u.psid_priority_array);
            break;
        case PSID_SSP:
            array_free(&permissions->u.psid_ssp_array);
            break;
        case PSID_PRIORITY_SSP:
            array_free(&permissions->u.psid_priority_ssp_array);
            break;
    }
}
void cme_permissions_array_free(struct cme_permissions_array* 
                permission_array){
    int i;
    if(permission_array->cme_permissions == NULL)
        return;
    for(i=0;i<permission_array->len;i++){
        cme_permissions_free(permission_array->cme_permissions+i);
    }
    free(permission_array->cme_permissions);
    permission_array->cme_permissions == NULL;
    permission_array->len = 0;
}

void certificate_chain_free(struct certificate_chain* certs_chain){
    int i=0;
    if(certs_chain->certs == NULL)
        return;
    for(i=0;i<certs_chain->len;i++){
       certificate_free(certs_chain->certs + i);
    }
    free(certs_chain->certs);
    certs_chain->certs = NULL;
    certs_chain->len = 0;
}


/**
 * alloced_lsis链表按照递增的顺序维护
 */
static void inline cme_lsis_insert(struct cme_db* cmdb,struct cme_alloced_lsis* lsis){
    struct list_head *head;
    struct cme_alloced_lsis *node;
    lock_wrlock(&cmdb->lock);
    head = &cmdb->cmhs.alloc_cmhs.cmh_init.list;
    list_for_each_entry(node,head,list){
        if(lsis->lsis < node->lsis){
            break;
        }     
    }
    list_add_tail(&lsis->list,&node->list);
    lock_unlock(&cmdb->lock);
}
/**
 * cmh_init链表按照递增的顺序维护
 */
static void inline cmh_init_insert(struct cme_db* cmdb,struct cmh_chain* cmh){
    struct list_head *head;
    struct cmh_chain *node;
    lock_wrlock(&cmdb->lock);
    head = &cmdb->cmhs.alloc_cmhs.cmh_init.list;
    list_for_each_entry(node,head,list){
        if(cmh->cmh < node->cmh){
            break;
        }     
    }
    list_add_tail(&cmh->list,&node->list);
    lock_unlock(&cmdb->lock);
}
/**************cert_info 红黑书函数操作开始************/
static int inline certid10_cmp(certid10* a,certid10* b){
    int i;
    for(i=0;i<10;i++){
        if(a->certid10[i] < b->certid10[i])
            return -1;
        if(a->certid10[i] > b->certid10[i])
            return 1;
    }
    return 0;
}
int cert_info_compare(struct rb_head* a,struct rb_head* b){
    struct cert_info *certinfoa,*certinfob;
    certinfoa = rb_entry(a,struct cert_info,rb);
    certinfob = rb_entry(b,struct cert_info,rb);
    return certid10_cmp(&certinfoa->certid10,&certinfob->certid10);
}
int cert_info_equal(struct rb_head* a,void* value){
    struct certid10* certid;
    struct cert_info *certinfoa;
    certid = (struct certid10*)value;
    certinfoa = rb_entry(a,struct cert_info,rb);
    return certid10_cmp(&certinfoa->certid10,certid);
}
void cert_info_init_rb(struct cert_info* certinfo){
    rb_init(&certinfo->rb,cert_info_compare,cert_info_equal);
}
static struct cert_info*  cert_info_insert(struct cert_info* root,struct cert_info* node){
    struct rb_head *rb;
    if( root != NULL)
        rb = rb_insert(&root->rb,&node->rb);
    else
        rb = rb_insert(NULL,&node->rb);
    return rb_entry(rb,struct cert_info,rb);
}
static struct cert_info* cert_info_find(struct cert_info* root,void* value){
    struct rb_head* rb;
    if(root == NULL)
        return NULL;
    rb = rb_find(&root->rb,value);
    if(rb == NULL)
        return NULL;
    return rb_entry(rb,struct cert_info,rb);   
}
static struct cert_info* cert_info_delete(struct cert_info* root,struct cert_info* node){
    struct rb_head* rb;
    if(root == NULL)
        return NULL;
    rb = rb_delete(&root->rb,&node->rb);
    return rb_entry(rb,struct cert_info,rb);
}
/**************cert_info 红黑书函数操作结束*************/
/************cmh_key_cert 红黑书函数操作开始*********/
int compare(struct rb_head *a,struct rb_head *b){
    struct cmh_key_cert *ckca,*ckcb;
    ckca = rb_entry(a,struct cmh_key_cert,rb);
    ckcb = rb_entry(b,struct cmh_key_cert,rb);
    if(ckca->cmh < ckcb->cmh)
        return -1;
    if(ckca->cmh == ckcb->cmh);
        return 0;
    return 1;
}
int equal(struct rb_head *a,void* value){
    struct cmh_key_cert *ckca;
    cmh mvalue = *(cmh*)value;
    ckca =  rb_entry(a,struct cmh_key_cert,rb);
    if(ckca->cmh < mvalue)
        return -1;
    if(ckca->cmh == mvalue)
        return 0;
    return 1;
}
void ckc_init_rb(struct cmh_key_cert* ckc){
    rb_init(&ckc->rb,compare,equal);
}
static inline struct cmh_key_cert*  ckc_insert(struct cmh_key_cert* root,struct cmh_key_cert* node){
    struct rb_head *rb;
    if( root != NULL)
        rb = rb_insert(&root->rb,&node->rb);
    else
        rb = rb_insert(NULL,&node->rb);
    return rb_entry(rb,struct cmh_key_cert,rb);
}
static inline struct cmh_key_cert*  ckc_find(struct cmh_key_cert* root,void* value){
    struct rb_head* rb;
    if(root == NULL)
        return NULL;
    rb = rb_find(&root->rb,value);
    if(rb == NULL)
        return NULL;
    return rb_entry(rb,struct cmh_key_cert,rb);
}
static inline struct cmh_key_cert*  ckc_delete(struct cmh_key_cert* root,struct cmh_key_cert* node){
    struct rb_head* rb;
    if(root == NULL)
        return NULL;
    rb = rb_delete(&root->rb,&node->rb);
    return rb_entry(rb,struct cmh_key_cert,rb);
}
/***************cmh_key_cert 红黑树操作函数结束**************/

/*
 * 通过cmh找到对应的证书,成功返回0，失败返回1,未测
 * */
int find_cert_by_cmh(struct sec_db *sdb, void *value, struct certificate *cert){
    struct cmh_key_cert *p = NULL;
    if(cert != NULL){
        lock_rdlock(&sdb->cme_db.lock);
        p = ckc_find(sdb->cme_db.cmhs.alloc_cmhs.cmh_key_cert ,value);
        if(!p){
            lock_unlock(&sdb->cme_db.lock);
            return 1;
        }
        certificate_cpy(cert, p->cert);
        lock_unlock(&sdb->cme_db.lock);
        return 0;
    }
    return 1;
}

result cme_lsis_request(struct sec_db* sdb,cme_lsis* lsis){
    struct cme_db  *cdb;
    struct list_head *head;
    struct cme_lsis_chain *node;
    struct cme_alloced_lsis *mlsis;
    if(lsis == NULL)
        return FAILURE;
    cdb = &(sdb->cme_db);
    lock_wrlock(&cdb->lock);
    head = &cdb->lsises.lsises.list;
    if( list_empty(head)){
        lock_unlock(&cdb->lock);
        wave_error_printf("lsis为空");
        return FAILURE;
    }
    node = list_entry(head->next,struct cme_lsis_chain,list);
    mlsis = (struct cme_alloced_lsis*)malloc(sizeof(struct cme_alloced_lsis));
    if(mlsis == NULL){
        lock_unlock(&cdb->lock);
        return FAILURE;    
    }
    list_del(&node->list);
    INIT(mlsis->data);
    mlsis->lsis = node->lsis;
    cme_lsis_insert(cdb,mlsis);
    free(node);
    lock_unlock(&cdb->lock);
    *lsis = mlsis->lsis;
    wave_printf(MSG_DEBUG,"分配一个lsis ：%d\n",*lsis);
    return SUCCESS;
}

result cme_cmh_request(struct sec_db* sdb,cmh* cmh){
    struct cme_db*  cdb;
    struct list_head *head;
    struct cmh_chain *node;
    if(cmh == NULL)
        return FAILURE;
    cdb  = &sdb->cme_db;
    lock_wrlock(&cdb->lock);
    head = &cdb->cmhs.cmh_chain.list;
    if( list_empty(head)){
        lock_unlock(&cdb->lock);
        wave_error_printf("cmh为空");
        return FAILURE;
    }
    node = list_entry(head->next,struct cmh_chain,list);
    list_del(&node->list);
    cmh_init_insert(cdb,node);
    lock_unlock(&cdb->lock);
    *cmh = node->cmh;
    wave_printf(MSG_DEBUG,"分配的cmh：%d\n",*cmh);
    return SUCCESS;
}
result cme_generate_keypair(struct sec_db* sdb,const cmh cmh,
                const pk_algorithm algorithm,
                string* pub_key){
    string mpuk,mprk;
    struct cme_db *cdb;
    struct list_head *cmh_init_head,*cmh_key_head;
    struct cmh_init *cmh_init_node;
    struct cmh_keypaired *cmh_keys_node,*new_keys_node;
    INIT(mpuk);
    INIT(mprk);
    if(pub_key == NULL || pub_key->buf != NULL)
        return FAILURE;
    cdb = &sdb->cme_db;
    //按照二哥提供的算法，我们生成一对密钥和公要

  
    pub_key->buf = (u8*)malloc(mpuk.len);
    if(pub_key->buf == NULL){
        wave_error_printf("内存分配失败");
        return FAILURE;
    }
    if( cme_store_keypair(sdb,cmh,algorithm,&mpuk,&mprk) == FAILURE){
        string_free(pub_key);
        return FAILURE;
    }
    string_cpy(pub_key,&mpuk);
    return SUCCESS;
}
result cme_store_keypair(struct sec_db* sdb,const cmh cmh,
                            const pk_algorithm algorithm,
                            const string* pub_key,
                            const string* pri_key){
    struct cme_db *cdb;
    struct list_head *cmh_init_head,*cmh_key_head;
    struct cmh_chain *cmh_init_node;
    struct cmh_keypaired *cmh_keys_node,*new_keys_node;
    if(pub_key == NULL || pub_key->buf == NULL || pri_key == NULL
            ||pri_key->buf == NULL)
        return FAILURE;
    cdb = &sdb->cme_db;
    lock_wrlock(&cdb->lock);
    cmh_init_head  = &cdb->cmhs.alloc_cmhs.cmh_init.list;
    cmh_key_head = &cdb->cmhs.alloc_cmhs.cmh_keys.list;
    list_for_each_entry(cmh_init_node,cmh_init_head,list){
        if(cmh_init_node->cmh == cmh){
            break;
        }
        if(cmh_init_node->cmh > cmh){
            lock_unlock(&cdb->lock);
            wave_error_printf("cmh_init %d 不存在",cmh);
            return FAILURE;
        }
    }
    if(&cmh_init_node->list == cmh_init_head){
        lock_unlock(&cdb->lock);
        wave_error_printf("cmh_init %d 不存在",cmh);
        return FAILURE;
    }
    new_keys_node = (struct cmh_keypaired*)malloc(sizeof(struct cmh_keypaired));
    if(new_keys_node == NULL){
        lock_unlock(&cdb->lock);
        wave_error_printf("内存分配失败");
        return FAILURE;
    }
    list_del(&cmh_init_node->list);
    free(cmh_init_node);
    INIT(*new_keys_node);
    new_keys_node->algorithm = algorithm;
    new_keys_node->cmh = cmh;
    string_cpy(&new_keys_node->private_key,pri_key);
    string_cpy(&new_keys_node->public_key,pub_key);

    list_for_each_entry(cmh_keys_node,cmh_key_head,list){
        if(cmh_keys_node->cmh > cmh){
            break;
        }
    }
    list_add_tail(&new_keys_node->list,&cmh_keys_node->list);
    lock_unlock(&cdb->lock);
    return SUCCESS;
}

static result  cert_info_init(struct sec_db* sdb,struct cert_info* certinfo,struct certificate* cert){
    crl_series series;
    certinfo->cert = cert;
    cert_info_init_rb(certinfo);
    //还有很多没有写。
    
}
result cme_store_cert(struct sec_db* sdb,const cmh cmh,
                        const certificate* cert,
                        const string* transfor){

    struct list_head *cmh_keys_head,*cmh_key_cert_head;
    struct cmh_keypaired *cmh_keys_node;
    struct cmh_key_cert *root,*new_key_cert_node = NULL;
    struct certificate* mcert = NULL;
    struct cert_info* certinfo = NULL;
    struct cme_db *cdb;
    cdb = &sdb->cme_db;
   
    mcert = (struct certificate*)malloc(sizeof(struct certificate));
    if(mcert == NULL){
        wave_error_printf("内存分配失败");
        goto fail;
    }
    INIT(*mcert);
    certinfo = (struct cert_info*)malloc(sizeof(struct cert_info));
    if(certinfo == NULL){
        wave_error_printf("内存分配失败");
        goto fail;
    }
    INIT(*certinfo);
    new_key_cert_node = (struct cmh_key_cert*)malloc(sizeof(struct cmh_key_cert));
    if(new_key_cert_node == NULL){
        wave_error_printf("内存分配失败");
        goto fail;
    }
    INIT(*new_key_cert_node);
    ckc_init_rb(new_key_cert_node);
    certificate_cpy(mcert,cert);
    cert_info_init(sdb,certinfo,mcert);
    new_key_cert_node->cmh = cmh;
    new_key_cert_node->cert = mcert;
    new_key_cert_node->cert_info = certinfo;
    
    lock_wrlock(&cdb->lock);
    cmh_keys_head = &cdb->cmhs.alloc_cmhs.cmh_keys.list;
    root= cdb->cmhs.alloc_cmhs.cmh_key_cert;
    list_for_each_entry(cmh_keys_node,cmh_keys_head,list){
        if(cmh_keys_node->cmh == cmh)
            break;
        if(cmh_keys_node->cmh > cmh){
            lock_unlock(&cdb->lock);
            wave_error_printf("没有找到cmh %d",cmh);
            goto fail;
        }
    }
    if(&cmh_keys_node->list == cmh_keys_head){
        lock_unlock(&cdb->lock);
        wave_error_printf("没有找到cmh %d",cmh);
        goto fail;
    }
    /*********
     *做私钥变换，然后赋值给new_key_cert_node;
     *
     */ 
    cdb->cmhs.alloc_cmhs.cmh_key_cert = ckc_insert(root,new_key_cert_node);
    cdb->certs = cert_info_insert(cdb->certs,certinfo);
    lock_unlock(&cdb->lock);
    list_del(&cmh_keys_node->list);
    cmh_keypaired_free(cmh_keys_node);
    free(cmh_keys_node);
    return SUCCESS;
fail:
    if(mcert != NULL){
        certificate_free(mcert);
        free(mcert);
    }
    if(certinfo != NULL){
        certinfo->cert = NULL;
        cert_info_free(certinfo);
        free(certinfo);
    }
    if(new_key_cert_node != NULL){
        free(new_key_cert_node);
    }
    return FAILURE;
}

result cme_store_cert_key(struct sec_db* sdb,const certificate* cert,
                            const string* pri_key){
    struct cert_info* certinfo,root;
    struct certificate* mcert; 
    struct cme_db* cdb;
    cdb = &sdb->cme_db;
    
    mcert = (struct certificate*)malloc(sizeof(struct certificate));
    if(mcert == NULL){
        wave_error_printf("内存分配失败");
        goto fail;
    }
    INIT(*mcert);
    certinfo = (struct cert_info*)malloc(sizeof(struct cert_info));
    if(certinfo == NULL){
        wave_error_printf("内存分配失败");
        goto fail;
    }
    INIT(*certinfo);
    certificate_cpy(mcert,cert);
    cert_info_init(sdb,certinfo,mcert);
    lock_wrlock(&cdb->lock);
    cdb->certs = cert_info_insert(cdb->certs,certinfo);
    lock_unlock(&cdb->lock);
fail:
    if(mcert != NULL){
        certificate_free(mcert);
        free(mcert);
    }
    if(certinfo != NULL){
        certinfo->cert = NULL;
        cert_info_free(certinfo);
        free(certinfo);
    }
    return FAILURE;
}

result cme_certificate_info_request(struct sec_db* sdb, 
                    enum identifier_type type,
                    string *identifier,
                    
                    string *certificate,
                    struct cme_permissions* permissions,
                    geographic_region* scope,
                    time64* last_crl_time,time64* next_crl_time,
                    bool* trust_anchor,bool* verified){
    result ret = FOUND;

}

result cme_construct_certificate_chain(struct sec_db* sdb,
                enum identifier_type type,
                string* identifier,
                struct certificate_chain* certificates,
                bool terminate_at_root,
                u32 max_chain_len,
                
                struct certificate_chain* certificate_chain,
                struct cme_permissions_array* permissions_array,
                struct geographic_region_array* regions,
                struct last_crl_times_array *last_crl_times_array,
                struct next_crl_times_array *next_crl_times_array,
                struct verified_array *verified_array){
    result ret = SUCCESS;
    struct certificate *certificate = NULL;
    bool trust_anchor;
    int i = 0, j = 0;
    string sign_id;
    string cert_encoded;
    string hash8;

    INIT(sign_id);
    INIT(hash8);
    cert_encoded.len = 0;
    cert_encoded.buf = malloc(sizeof(500));
    if(!cert_encoded.buf)
        goto fail;
    memset(cert_encoded.buf, 0, 500);

    if(certificate_chain != NULL){
        certificate_chain->certs = malloc(sizeof(struct certificate)*max_chain_len);
        if(!certificate_chain->certs)
            goto fail;
        memset(certificate_chain->certs, 0, sizeof(struct certificate)*max_chain_len);
        certificate_chain->len = 0;
    }

    if(permissions_array != NULL){
        permissions_array->cme_permissions = malloc(sizeof(struct cme_permissions)*max_chain_len);
        if(!permissions_array->cme_permissions)
            goto fail;
        memset(permissions_array->cme_permissions, 0, sizeof(struct cme_permissions)*max_chain_len);
        permissions_array->len = 0;
    }

    if(regions != NULL){
        regions->regions = malloc(sizeof(struct geographic_region)*max_chain_len);
        if(!regions->regions)
            goto fail;
        memset(regions->regions, 0, sizeof(struct geographic_region)*max_chain_len);
        regions->len = 0;
    }

    if(last_crl_times_array != NULL){
        last_crl_times_array->last_crl_time = malloc(sizeof(time64)*max_chain_len);
        if(!last_crl_times_array->last_crl_time)
            goto fail;
        memset(last_crl_times_array->last_crl_time, 0, sizeof(time64)*max_chain_len);
        last_crl_times_array->last_crl_time = 0;
    }

    if(next_crl_times_array != NULL){
        next_crl_times_array->next_crl_time = malloc(sizeof(time64)*max_chain_len);
        if(!next_crl_times_array->next_crl_time)
            goto fail;
        memset(next_crl_times_array->next_crl_time, 0, sizeof(time64)*max_chain_len);
        next_crl_times_array->len = 0;
    }

    if(verified_array != NULL){
        verified_array->verified = malloc(sizeof(bool)*max_chain_len);
        if(!verified_array->verified)
            goto fail;
        memset(verified_array->verified, 0, sizeof(bool)*max_chain_len);
        verified_array->len = 0;
    }

    if(type == ID_CERTIFICATE)
        certificate = &certificates->certs[0];
    else
        string_cpy(&sign_id, identifier);

construct_chain:
    if(i != 0){
        sign_id.len = 8;
        if(sign_id.buf == NULL)
            sign_id.buf = malloc(sizeof(8));
        if(sign_id.buf == NULL)
            goto fail;
        memcpy(sign_id.buf, certificate->unsigned_certificate.u.no_root_ca.signer_id.hashedid8, 8);
        certificate = NULL;
    }

    if(certificate == NULL)
        ret = cme_certificate_info_request(sdb, ID_HASHEDID8, &sign_id, &cert_encoded, &(permissions_array->cme_permissions[i]), 
                &(regions->regions[i]), &(last_crl_times_array->last_crl_time[i]), &(next_crl_times_array->next_crl_time[i]), 
                &trust_anchor, &(verified_array->verified[i]));
    else{
        certificate_2_buf(certificate, cert_encoded.buf, 500);
        ret = cme_certificate_info_request(sdb, ID_CERTIFICATE, &cert_encoded, &cert_encoded, &(permissions_array->cme_permissions[i]), 
                &(regions->regions[i]), &(last_crl_times_array->last_crl_time[i]), &(next_crl_times_array->next_crl_time[i]), 
                &trust_anchor, &(verified_array->verified[i]));
    }
   
    if(ret != FOUND && ret != CERTIFICATE_NOT_FOUND)
        goto fail;
   
    if(ret == CERTIFICATE_NOT_FOUND && certificate == NULL){
        if(type != ID_CERTIFICATE){
            ret = NOT_ENOUGH_INFORMATION_TO_CONSTRUT_CHAIN;
            goto fail;
        }
        for(j = 0; j < certificates->len; j++){
            certificate_2_hash8(&certificates->certs[i],&hash8);//i need this
            if(string_cmp(&hash8, &sign_id) == 0){
                if(certificates->certs[i].unsigned_certificate.holder_type == ROOT_CA){
                    ret = CHAINE_ENDED_AT_UNKNOWN_ROOT;
                    goto fail;
                }
                certificate = &certificates->certs[i];
                goto construct_chain;
            }
        }
        ret = NOT_ENOUGH_INFORMATION_TO_CONSTRUT_CHAIN;
        goto fail;
    }
   
    if(ret == CERTIFICATE_NOT_FOUND && certificate != NULL){
        verified_array->verified[i] = false;
    }
    certificate_cpy(&certificate_chain->certs[i], certificate);
   
    i++;
    if(i > max_chain_len){
        ret = CHAINE_TOO_LONG;
        goto fail;
    }
    
    if(terminate_at_root == false){
        if(trust_anchor == false)
            goto construct_chain;
    }
    else{
        if(certificate->unsigned_certificate.holder_type != ROOT_CA)
            goto construct_chain;
    }

    ret = SUCCESS;
fail:
    certificate = NULL;
    string_free(&sign_id);
    string_free(&cert_encoded);
    string_free(&hash8);
    return ret;
}
