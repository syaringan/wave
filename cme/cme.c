#include "cme.h"
#include "../data/data_handle.h"
#include"../sec/sec.h"
#include <stdlib.h>
#include<time.h>
#define INIT(n) memset(&n,0,sizeof(n))
#define MAX_PERMISSIONS_LENGTH 8
#define MAX_RECTANGLES_ENTRIES_NUM 12
#define MAX_POLYGON_VERTICES_ENTRIES_NUM 12

#define IMPLICT 3
#define EXPLICT 2

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

void verified_array_free(struct verified_array *verified_array){
    if(verified_array->verified == NULL){
        return ;
    }
    free(verified_array->verified);
    verified_array->verified = NULL;
    verified_array->len = 0;
}
void time32_array_free(struct time32_array *array){
    if(array->times == NULL){
        return;
    }
    free(array->times);
    array->times = NULL;
    array->len = 0;
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
void geographic_region_array_free(struct geographic_region_array* regions){
    if(regions->regions == NULL)
        return;
    int i;
    for(i=0;i<regions->len;i++){
        geographic_region_free(regions->regions+i);
    }
    free(regions->regions);
    regions->regions = NULL;
    regions->len = 0;
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
 * 通过cmh找到对应的证书,成功返回0，失败返回-1,未测
 * */
int find_cert_by_cmh(struct sec_db *sdb, void *value, struct certificate *cert){
    struct cmh_key_cert *p = NULL;
    if(cert != NULL){
        lock_rdlock(&sdb->cme_db.lock);
        p = ckc_find(sdb->cme_db.cmhs.alloc_cmhs.cmh_key_cert ,value);
        if(!p){
            lock_unlock(&sdb->cme_db.lock);
            return -1;
        }
        certificate_cpy(cert, p->cert);
        lock_unlock(&sdb->cme_db.lock);
        return 0;
    }
    return -1;
}
int find_cert_prikey_by_cmh(struct sec_db* sdb,cmh cmh,certificate* cert,string* privatekey){
    struct cmh_key_cert *p = NULL;
    if(privatekey == NULL || privatekey->buf != NULL){
        wave_error_printf("string 里面可能有野指针");
        return -1;
    }
    if(cert != NULL){
        lock_rdlock(&sdb->cme_db.lock);
        p = ckc_find(sdb->cme_db.cmhs.alloc_cmhs.cmh_key_cert ,&cmh);
        if(!p){
            lock_unlock(&sdb->cme_db.lock);
            return -1;
        }
        certificate_cpy(cert, p->cert);
        string_cpy(privatekey,&p->private_key);
        lock_unlock(&sdb->cme_db.lock);
        return 0;
    }
    return -1;
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
result cme_generate_keypair(struct sec_db* sdb,  cmh cmh,
                  pk_algorithm algorithm,
                string* pub_key_x,string* pub_key_y){
    string mprk;
    result res = SUCCESS;

    INIT(mprk);

    if(pub_key_x == NULL || pub_key_x->buf != NULL ||
            pub_key_y == NULL || pub_key_y->buf != NULL){
        wave_error_printf("参数部队 %s %d",__FILE__,__LINE__ );
        res = FAILURE;
        goto end;
    }
    //按照二哥提供的算法，我们生成一对密钥和公要
    switch(algorithm){
        case ECDSA_NISTP224_WITH_SHA224:
            if( crypto_ECDSA224_get_privatekey(&mprk)){
                res = FAILURE;
                goto end;
            }
            if( crypto_ECDSA224_get_publickey(&mprk,pub_key_x,pub_key_y)){
                res = FAILURE;
                goto end;
            }
            break;
        case ECDSA_NISTP256_WITH_SHA256:
            if( crypto_ECDSA256_get_privatekey(&mprk)){
                res = FAILURE;
                goto end;
            }
            if( crypto_ECDSA256_get_publickey(&mprk,pub_key_x,pub_key_y)){
                res = FAILURE;
                goto end;
            }
            break;
        case ECIES_NISTP256:
            if( crypto_ECIES256_get_privatekey(&mprk)){
                res = FAILURE;
                goto end;
            }
            if( crypto_ECIES256_get_publickey(&mprk,pub_key_x,pub_key_y)){
                res = FAILURE;
                goto end;
            }
            break;
        default:
            wave_error_printf("出现了不应该有的指 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
    }
    if( res = cme_store_keypair(sdb,cmh,algorithm,pub_key_x,pub_key_y,&mprk) ){
        res = FAILURE;
        goto end;
    }
    goto end;
end:
    string_free(&mprk);
    return res;
}
result cme_store_keypair(struct sec_db* sdb,  cmh cmh,
                              pk_algorithm algorithm,
                              string* pub_key_x,
                              string* pub_key_y,
                              string* pri_key){
    struct cme_db *cdb;
    struct list_head *cmh_init_head,*cmh_key_head;
    struct cmh_chain *cmh_init_node;
    struct cmh_keypaired *cmh_keys_node,*new_keys_node;
    if(pub_key_x == NULL || pub_key_x->buf == NULL || pub_key_y == NULL || pub_key_y->buf == NULL || 
            pri_key == NULL || pri_key->buf == NULL){
        wave_error_printf("参数有问题 %s %d",__FILE__,__LINE__);
        return FAILURE;
    }
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
    string_cpy(&new_keys_node->public_key_x,pub_key_x);
    string_cpy(&new_keys_node->public_key_y,pub_key_y);

    list_for_each_entry(cmh_keys_node,cmh_key_head,list){
        if(cmh_keys_node->cmh > cmh){
            break;
        }
    }
    list_add_tail(&new_keys_node->list,&cmh_keys_node->list);
    lock_unlock(&cdb->lock);
    return SUCCESS;
}
//这个函数是用来判断那写对于cme来说新的cert是否吊销了，而不是已经存在本的证书了。
static int is_certificate_revoked(struct sec_db *sdb,certificate* cert){
    struct cme_db *cdb;
    struct list_head *head,*ca_head,*revoked_head;
    struct crl_head *crl_temp;
    struct crl_ca_id *crl_ca_temp;
    struct revoked_certs *revoked_temp;
    certid10 certid;
    if( cert->unsigned_certificate.expiration < time(NULL))
        return true;
    if( certificate_2_certid10(cert,&certid)){
       return -1; 
    }
    if(cert->unsigned_certificate.holder_type == ROOT_CA){
        //这里应该怎么处理 是root_ca 我就相信嘛？？？我得找个标准的几个ca来存起来看把。我这里就先简单处理，我相信他
        
        wave_printf(MSG_WARNING,"这里该不该相信啊，，我觉得这里外部是可以欺骗我的 %s %d\n",__FILE__,__LINE__);
        return false;
    }
    cdb = &sdb->cme_db;
    lock_rdlock(&cdb->lock);
    head = &cdb->crls.list;
    list_for_each_entry(crl_temp,head,list){
        if(crl_temp->crl_series == cert->unsigned_certificate.crl_series){
            ca_head = &crl_temp->ca_id_list.list;
            list_for_each_entry(crl_ca_temp,ca_head,list){
                if( hashedid8_equal(&crl_ca_temp->ca_id,&cert->unsigned_certificate.u.no_root_ca.signer_id)){
                    revoked_head = &crl_ca_temp->revoked_certs.list;
                    list_for_each_entry(revoked_temp,revoked_head,list){
                        if( certid10_equal(&certid,&revoked_temp->certid)){
                            lock_unlock(&cdb->lock);
                            return true;
                        }
                    }
                }
            }
        }
    }
    lock_unlock(&cdb->lock);
    return false; 
}
static int is_certificate_verified(struct sec_db* sdb,struct certificate* cert){
    string identifier;
    struct verified_array verifieds;
    int i,answer = false;
    result res;
    
    INIT(identifier);
    INIT(verifieds);
    
    if(cert->unsigned_certificate.holder_type != ROOT_CA){
        hashedid8_2_string(&cert->unsigned_certificate.u.no_root_ca.signer_id,&identifier);
        res = cme_construct_certificate_chain(sdb,ID_HASHEDID8,&identifier,NULL,false,100,NULL,NULL,NULL,NULL,NULL,&verifieds);
        if(res != SUCCESS){
            answer = -1;
            goto end;
        }
        for(i=0;i<verifieds.len;i++){
            if( *(verifieds.verified+i) == false){
                answer = false;
                goto end;
            }
        }
        answer = true;
        goto end;
    }
    else{
        wave_printf(MSG_WARNING,"这里我觉得不应该是root——ca的 %s %d",__FILE__,__LINE__);
    }
    answer = true;
    goto end;
end:
    string_free(&identifier);
    verified_array_free(&verifieds);
    return res;
}
static result get_crl_time_by_certificate(struct sec_db* sdb,certificate* cert,time32 *last_crl_time,time32 *next_crl_time){
    struct cme_db *cdb;
    hashedid8 ca_id;
    struct list_head *ca_id_head,*series_head,*serial_head;
    struct crl_head* crl_series_temp;
    struct crl_ca_id* crl_ca_temp;
    struct crl_serial_number* crl_serial_temp;
    
    if(cert->unsigned_certificate.holder_type == ROOT_CA){
        if( certificate_2_hashedid8(cert,&ca_id)){
            return FAILURE;
        }
    }
    else{
        hashedid8_cpy(&ca_id,&cert->unsigned_certificate.u.no_root_ca.signer_id);
    }
    cdb = &sdb->cme_db;
    lock_rdlock(&cdb->lock);
    series_head = &cdb->crls.list;
    list_for_each_entry(crl_series_temp,series_head,list){
        if(crl_series_temp->crl_series == cert->unsigned_certificate.crl_series){
            ca_id_head = &crl_series_temp->ca_id_list.list;
            list_for_each_entry(crl_ca_temp,ca_id_head,list){
                if( hashedid8_equal(&crl_ca_temp->ca_id ,&ca_id)){
                    serial_head = &crl_ca_temp->crl_info_list.list;
                    if(serial_head->prev == serial_head){
                        return FAILURE; 
                    }
                    crl_serial_temp = list_entry(serial_head->prev,struct crl_serial_number,list);
                    if(last_crl_time != NULL)
                        *last_crl_time = crl_serial_temp->issue_date;
                    if(next_crl_time != NULL)
                        *next_crl_time = crl_serial_temp->next_crl_time;
                    return SUCCESS;
                }
            }
        }
    }
    return FAILURE;
}
static void del_certificate_by_certid10(struct sec_db* sdb,certid10* certid){
    struct cme_db *cdb;
    struct cert_info *cinfo;

    cdb = &sdb->cme_db;
    lock_wrlock(&cdb->lock);
    cinfo = cert_info_find(cdb->certs,&certid);
    if(cinfo == NULL){
        lock_unlock(&cdb->lock);
        return;
    }
    cinfo->key_cert->cert_info = NULL;
    cdb->certs = cert_info_delete(cdb->certs,cinfo);
    lock_unlock(&cdb->lock);
    cert_info_free(cinfo);
    free(cinfo);
    return;
}
static result cert_info_init(struct sec_db* sdb,struct cert_info* certinfo,struct certificate* cert){
    result res = SUCCESS;

    certinfo->cert = cert;
    cert_info_init_rb(certinfo);
    if(certificate_2_certid10(cert,&certinfo->certid10)){
        res = FAILURE;
        goto end;
    }
    certinfo->revoked = is_certificate_revoked(sdb,cert);
    if(certinfo->revoked == -1){
        res = FAILURE;
        goto end;
    }
    certinfo->expriry = cert->unsigned_certificate.expiration * US_TO_S;
    certinfo->verified = is_certificate_verified(sdb,cert);
    if(certinfo->verified == -1){
        res = FAILURE;
        goto end;
    }
    certinfo->trust_anchor = false;
    certinfo->key_cert = NULL;
    goto end;
end:
    return res;
}
result cme_store_cert(struct sec_db* sdb,  cmh cmh,
                          certificate* cert,
                          string* transfor){

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
    certinfo->key_cert = new_key_cert_node;
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

result cme_store_cert_key(struct sec_db* sdb,  certificate* cert,
                              string* pri_key){
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

int get_region(geographic_region *src, geographic_region *dst, enum holder_type type){
    if(!src || !dst){
        wave_error_printf("输入空指针");
        return -1;
    }
    int reg_len = 0;
    if(src->region_type == FROM_ISSUER){
        if(type == ROOT_CA){
            wave_error_printf("root ca cant from issuer!");
            return -1;
        }
        dst->region_type = FROM_ISSUER;
    }
    else if(src->region_type == CIRCLE){
        dst->region_type = CIRCLE;
        dst->u.circular_region = src->u.circular_region;
    }
    else if(src->region_type == RECTANGLE){
        dst->region_type = RECTANGLE;
        reg_len = src->u.rectangular_region.len;
        dst->u.rectangular_region.len = reg_len;
        dst->u.rectangular_region.buf = malloc(sizeof(rectangular_region)*reg_len);
        if(!dst->u.rectangular_region.buf){
            wave_error_printf("内存分配失败");
            return -1;
        }
        memcpy(dst->u.rectangular_region.buf, src->u.rectangular_region.buf,
                sizeof(rectangular_region)*reg_len);
    }
    else if(src->region_type == POLYGON){
        dst->region_type = POLYGON;
        reg_len = src->u.polygonal_region.len;
        dst->u.polygonal_region.len = reg_len;
        dst->u.polygonal_region.buf = malloc(sizeof(two_d_location)*reg_len);
        if(!dst->u.polygonal_region.buf){
            wave_error_printf("内存分配失败");
            return -1;
        }
        memcpy(dst->u.polygonal_region.buf, src->u.polygonal_region.buf,
                sizeof(two_d_location)*reg_len);
    }
    else if(src->region_type == NONE){
        dst->region_type = NONE;
    }
    else{
        wave_error_printf("错误的region_type");
        return -1;
    }
    return 0;
}

int get_permission_from_certificate(certificate *cert,

                                    struct cme_permissions *permission,
                                    geographic_region *scope){
    int ret = 0;
    int i = 0;
    int per_len = 0;
    int reg_len = 0;
    holder_type_flags types;

    switch(cert->unsigned_certificate.holder_type){
        case SDE_ANONYMOUS:
            if(permission != NULL){            
                if(cert->unsigned_certificate.scope.u.anonymous_scope.permissions.type == FROM_ISSUER){
                    permission->type = INHERITED_NOT_FOUND;
                }
                else{
                    permission->type = PSID_SSP;
                    per_len = cert->unsigned_certificate.scope.u.anonymous_scope.permissions.u.permissions_list.len;
                    permission->u.psid_ssp_array.len = per_len;
                    permission->u.psid_ssp_array.buf = malloc(sizeof(psid_ssp)*per_len);
                    if(!permission->u.psid_array.buf){
                        wave_error_printf("内存分配失败");
                        return -1;
                    }
                    for(i = 0; i < per_len; i++){
                        permission->u.psid_ssp_array.buf[i].psid = 
                            (cert->unsigned_certificate.scope.u.anonymous_scope.permissions.u.permissions_list.buf+i)->psid;
                    
                        permission->u.psid_ssp_array.buf[i].service_specific_permissions.len = 
                            (cert->unsigned_certificate.scope.u.anonymous_scope.permissions.u.permissions_list.buf+i)->service_specific_permissions.len;

                        permission->u.psid_ssp_array.buf[i].service_specific_permissions.buf = 
                            malloc(sizeof(u8)*permission->u.psid_ssp_array.buf[i].service_specific_permissions.len);

                        if(!permission->u.psid_ssp_array.buf[i].service_specific_permissions.buf){
                            wave_error_printf("malloc error!");
                            return -1;
                        }

                        memcpy(permission->u.psid_ssp_array.buf[i].service_specific_permissions.buf, 
                                    (cert->unsigned_certificate.scope.u.anonymous_scope.permissions.u.permissions_list.buf+i)->service_specific_permissions.buf,
                                    permission->u.psid_ssp_array.buf[i].service_specific_permissions.len);
                    }
                }
            }
            if(scope != NULL){
                if(get_region(&cert->unsigned_certificate.scope.u.anonymous_scope.region, scope, SDE_ANONYMOUS)){
                    wave_error_printf("get region error!");
                    return -1;
                }
            }
            break;
        case SDE_IDENTIFIED_NOT_LOCALIZED:
            if(permission != NULL){
                if(cert->unsigned_certificate.scope.u.id_non_loc_scope.permissions.type == FROM_ISSUER){
                    permission->type = INHERITED_NOT_FOUND;
                }
                else{
                    permission->type = PSID_SSP;
                    per_len = cert->unsigned_certificate.scope.u.id_non_loc_scope.permissions.u.permissions_list.len;
                    permission->u.psid_ssp_array.len = per_len;
                    permission->u.psid_ssp_array.buf = malloc(sizeof(psid_ssp)*per_len);
                    if(!permission->u.psid_array.buf){
                        wave_error_printf("内存分配失败");
                        return -1;
                    }
                    for(i = 0; i < per_len; i++){
                        permission->u.psid_ssp_array.buf[i].psid = 
                            (cert->unsigned_certificate.scope.u.id_non_loc_scope.permissions.u.permissions_list.buf+i)->psid;

                        permission->u.psid_ssp_array.buf[i].service_specific_permissions.len = 
                            (cert->unsigned_certificate.scope.u.id_non_loc_scope.permissions.u.permissions_list.buf+i)->service_specific_permissions.len;

                        permission->u.psid_ssp_array.buf[i].service_specific_permissions.buf = 
                            malloc(sizeof(u8)*permission->u.psid_ssp_array.buf[i].service_specific_permissions.len);

                        if(!permission->u.psid_ssp_array.buf[i].service_specific_permissions.buf){
                            wave_error_printf("malloc error!");
                            return -1;
                        }

                        memcpy(permission->u.psid_ssp_array.buf[i].service_specific_permissions.buf, 
                            (cert->unsigned_certificate.scope.u.id_non_loc_scope.permissions.u.permissions_list.buf+i)->service_specific_permissions.buf,
                            permission->u.psid_ssp_array.buf[i].service_specific_permissions.len);
                    }
                }
            }
            if(scope != NULL){
                scope->region_type = FROM_ISSUER;
            }
            break;
        case SDE_IDENTIFIED_LOCALIZED:
            if(permission != NULL){            
                if(cert->unsigned_certificate.scope.u.id_scope.permissions.type == FROM_ISSUER){
                    permission->type = INHERITED_NOT_FOUND;
                }
                else{
                    permission->type = PSID_SSP;
                    per_len = cert->unsigned_certificate.scope.u.id_scope.permissions.u.permissions_list.len;
                    permission->u.psid_ssp_array.len = per_len;
                    permission->u.psid_ssp_array.buf = malloc(sizeof(psid_ssp)*per_len);
                    if(!permission->u.psid_array.buf){
                        wave_error_printf("内存分配失败");
                        return -1;
                    }
                    for(i = 0; i < per_len; i++){
                        permission->u.psid_ssp_array.buf[i].psid = 
                            cert->unsigned_certificate.scope.u.id_scope.permissions.u.permissions_list.buf[i].psid;
                    
                        permission->u.psid_ssp_array.buf[i].service_specific_permissions.len = 
                    cert->unsigned_certificate.scope.u.id_scope.permissions.u.permissions_list.buf[i].service_specific_permissions.len;

                        permission->u.psid_ssp_array.buf[i].service_specific_permissions.buf = 
                            malloc(sizeof(u8)*permission->u.psid_ssp_array.buf[i].service_specific_permissions.len);

                        if(!permission->u.psid_ssp_array.buf[i].service_specific_permissions.buf){
                            wave_error_printf("malloc error!");
                            return -1;
                        }

                        memcpy(permission->u.psid_ssp_array.buf[i].service_specific_permissions.buf, 
                    cert->unsigned_certificate.scope.u.id_scope.permissions.u.permissions_list.buf[i].service_specific_permissions.buf,
                    permission->u.psid_ssp_array.buf[i].service_specific_permissions.len);
                    }
                }
            }
            if(scope != NULL){
                if(get_region(&cert->unsigned_certificate.scope.u.id_scope.region, scope, SDE_ANONYMOUS)){
                    wave_error_printf("get region error!");
                    return -1;
                }
            }
            break;
        case SDE_CA:
        case SDE_ENROLMENT:
            if(permission != NULL){
                if(cert->unsigned_certificate.scope.u.sde_ca_scope.permissions.type == FROM_ISSUER){
                    permission->type = INHERITED_NOT_FOUND;
                }
                else{
                    permission->type = PSID;
                    per_len = cert->unsigned_certificate.scope.u.sde_ca_scope.permissions.u.permissions_list.len;
                    permission->u.psid_array.len = per_len;
                    permission->u.psid_array.buf = malloc(sizeof(psid)*per_len);
                    if(!permission->u.psid_array.buf){
                        wave_error_printf("内存分配失败");
                        return -1;
                    }
                    memcpy(permission->u.psid_array.buf, 
                            cert->unsigned_certificate.scope.u.sde_ca_scope.permissions.u.permissions_list.buf, 
                            per_len*sizeof(psid));
                }
            }
            if(scope != NULL){
                if(get_region(&cert->unsigned_certificate.scope.u.sde_ca_scope.region, scope, SDE_CA)){
                    wave_error_printf("get region error!");
                    return -1;
                }
            }
            break;
        case WSA:
            if(permission != NULL){
                if(cert->unsigned_certificate.scope.u.wsa_scope.permissions.type == FROM_ISSUER){
                    permission->type = INHERITED_NOT_FOUND;
                }
                else{
                    permission->type = PSID_PRIORITY_SSP;
                    per_len = cert->unsigned_certificate.scope.u.wsa_scope.permissions.u.permissions_list.len;
                    permission->u.psid_priority_ssp_array.len = per_len;
                    permission->u.psid_priority_ssp_array.buf = malloc(sizeof(psid_priority_ssp)*per_len);
                    if(!permission->u.psid_priority_ssp_array.buf){
                        wave_error_printf("内存分配失败");
                        return -1;
                    }
                    for(i = 0; i < per_len; i++){
                        permission->u.psid_priority_ssp_array.buf[i].psid = 
                            cert->unsigned_certificate.scope.u.wsa_scope.permissions.u.permissions_list.buf[i].psid;

                        permission->u.psid_priority_ssp_array.buf[i].max_priority = 
                            cert->unsigned_certificate.scope.u.wsa_scope.permissions.u.permissions_list.buf[i].max_priority;
                    
                        permission->u.psid_priority_ssp_array.buf[i].service_specific_permissions.len = 
                            cert->unsigned_certificate.scope.u.wsa_scope.permissions.u.permissions_list.buf[i].service_specific_permissions.len;

                        permission->u.psid_priority_ssp_array.buf[i].service_specific_permissions.buf = 
                            malloc(sizeof(u8)*permission->u.psid_priority_ssp_array.buf[i].service_specific_permissions.len);

                        if(!permission->u.psid_priority_ssp_array.buf[i].service_specific_permissions.buf){
                            wave_error_printf("malloc error!");
                            return -1;
                        }

                        memcpy(permission->u.psid_priority_ssp_array.buf[i].service_specific_permissions.buf, 
                            cert->unsigned_certificate.scope.u.wsa_scope.permissions.u.permissions_list.buf[i].service_specific_permissions.buf,
                            permission->u.psid_priority_ssp_array.buf[i].service_specific_permissions.len);
                    }
                }
            }
            if(scope != NULL){
                if(get_region(&cert->unsigned_certificate.scope.u.wsa_scope.region, scope, WSA)){
                    wave_error_printf("get region error!");
                    return -1;
                }
            }
            break;
        case WSA_CA:
        case WSA_ENROLMENT:
            if(permission != NULL){
                if(cert->unsigned_certificate.scope.u.wsa_ca_scope.permissions.type == FROM_ISSUER){
                    permission->type = INHERITED_NOT_FOUND;
                }
                else{
                    permission->type = PSID_PRIORITY;
                    per_len = cert->unsigned_certificate.scope.u.wsa_ca_scope.permissions.u.permissions_list.len;
                    permission->u.psid_priority_array.len = per_len;
                    permission->u.psid_priority_array.buf = malloc(sizeof(psid_priority)*per_len);
                    if(!permission->u.psid_priority_array.buf){
                        wave_error_printf("内存分配失败");
                        return -1;
                    }
                    memcpy(permission->u.psid_priority_array.buf, 
                            cert->unsigned_certificate.scope.u.wsa_ca_scope.permissions.u.permissions_list.buf, 
                            per_len*sizeof(psid_priority));
                }
            }
            if(scope != NULL){
                if(get_region(&cert->unsigned_certificate.scope.u.wsa_ca_scope.region, scope, WSA)){
                    wave_error_printf("get region error!");
                    return -1;
                }
            }
            break;
        case CRL_SIGNER:
            wave_error_printf("type is crl signer, no permissions");
            return -1;
        case ROOT_CA:
            if(permission != NULL){
                types = cert->unsigned_certificate.scope.u.root_ca_scope.permitted_holder_types;
                if(types&FLAGS_SDE_ANONYMOUS || types&FLAGS_SDE_IDENTIFIED_NOT_LOCALIZED || types&FLAGS_SDE_IDENTIFIED_LOCALIZED 
                        || types&FLAGS_SDE_ENROLMENT || types&FLAGS_SDE_CA){
                    if(cert->unsigned_certificate.scope.u.root_ca_scope.flags_content.secure_data_permissions.type == 
                            ARRAY_TYPE_FROM_ISSUER){
                        wave_error_printf("root_ca_scope不能是from issuer");
                        return -1;
                    }
                    permission->type = PSID;
                    per_len = cert->unsigned_certificate.scope.u.root_ca_scope.flags_content.secure_data_permissions.u.permissions_list.len;
                    permission->u.psid_array.len = per_len;
                    permission->u.psid_array.buf = malloc(sizeof(psid)*per_len);
                    if(!permission->u.psid_array.buf){
                        wave_error_printf("内存分配失败");
                        return -1;
                    }
                    memcpy(permission->u.psid_array.buf, 
                        cert->unsigned_certificate.scope.u.root_ca_scope.flags_content.secure_data_permissions.u.permissions_list.buf, 
                        per_len*sizeof(psid));
                }
                else if(types&FLAGS_WSA || types&FLAGS_WSA_ENROLMENT || types&FLAGS_WSA_CA){
                    if(cert->unsigned_certificate.scope.u.root_ca_scope.flags_content.wsa_permissions.type == 
                            ARRAY_TYPE_FROM_ISSUER){
                        wave_error_printf("root_ca_scope不能是from issuer");
                        return -1;
                    }
                    permission->type = PSID_PRIORITY;
                    per_len = cert->unsigned_certificate.scope.u.root_ca_scope.flags_content.wsa_permissions.u.permissions_list.len;
                    permission->u.psid_priority_array.len = per_len;
                    permission->u.psid_array.buf = malloc(sizeof(psid_priority)*per_len);
                    if(!permission->u.psid_array.buf){
                        wave_error_printf("内存分配失败");
                        return -1;
                    }
                    memcpy(permission->u.psid_priority_array.buf, 
                            cert->unsigned_certificate.scope.u.root_ca_scope.flags_content.wsa_permissions.u.permissions_list.buf, 
                            per_len*sizeof(psid));
                }
                else{
                    wave_error_printf("错误的holderTypeFlags");
                    return -1;
                }
            }
            if(scope != NULL){
                if(get_region(&cert->unsigned_certificate.scope.u.root_ca_scope.region, scope, ROOT_CA)){
                    wave_error_printf("get region error!");
                    return -1;
                }
            }
            break;
        default:
            return -1;
    }
    return 0;
}

result cme_certificate_info_request(struct sec_db* sdb, 
                    enum identifier_type type,
                    string *identifier,
                    
                    string *certificate,
                    struct cme_permissions* permissions,
                    geographic_region* scope,
                    time32* last_crl_time,time32* next_crl_time,
                    bool* trust_anchor,bool* verified){
    result ret = FAILURE;
    bool trusted;
    struct certificate cert_decoded;
    struct cert_info cert_info;
    string signer_id;

    INIT(signer_id);
    INIT(cert_decoded);
    INIT(cert_info);

    if(get_cert_info_by_certid(sdb, type, identifier, &cert_info)){
        ret = CERTIFICATE_NOT_FOUND;
        if(type == ID_CERTIFICATE){
            if(next_crl_time != NULL){
                if(string_2_certificate(identifier, &cert_decoded)){
                    wave_error_printf("证书解码失败!");
                    ret = FAILURE;
                    goto fail;
                }
                *next_crl_time = get_next_crl_time_info(sdb, cert_decoded.unsigned_certificate.crl_series, 
                        &cert_decoded.unsigned_certificate.u.no_root_ca.signer_id);
            }
        }
        goto fail;
    }

    if(!cert_info.revoked){
        ret = CERTIFICATE_REVOKED;
        goto fail;
    }

    if(cert_info.next_recieve_crl < time(NULL) || cert_info.expriry / US_TO_S < time(NULL)){
        ret = CERTIFICATE_NOT_TRUSTED;
        goto fail;
    }
    ret = FOUND;
    if(verified != NULL){
        *verified = cert_info.verified;
    }
    if(certificate != NULL){
        if(certificate_2_string(cert_info.cert, certificate)){
            wave_error_printf("证书编码失败");
            ret = FAILURE;
            goto fail;
        }
    }
    get_crl_time_by_certificate(sdb,&cert_info.certid,last_crl_time,next_crl_time);
    if(last_crl_time != NULL){
        *last_crl_time = cert_info.last_recieve_crl;
    }
    if(next_crl_time != NULL){
        *next_crl_time = cert_info.next_recieve_crl;
    }

    if(get_permission_from_certificate(cert_info.cert, permissions, scope)){
        wave_error_printf("提取证书权限失败");
        ret = FAILURE;
        goto fail;
    }
    if(trust_anchor != NULL){
        *trust_anchor = cert_info.trust_anchor;
    }
    if(permissions != NULL){
        switch(permissions->type){
            case PSID:
                if(permissions->u.psid_array.len > MAX_PERMISSIONS_LENGTH){
                    ret = TOO_MANY_ENTRIES_IN_PERMISSON_ARRAY;
                    goto fail;
                }
                break;
            case PSID_PRIORITY:
                if(permissions->u.psid_priority_array.len > MAX_PERMISSIONS_LENGTH){
                    ret = TOO_MANY_ENTRIES_IN_PERMISSON_ARRAY;
                    goto fail;
                }
                break;
            case PSID_SSP:
                if(permissions->u.psid_ssp_array.len > MAX_PERMISSIONS_LENGTH){
                    ret = TOO_MANY_ENTRIES_IN_PERMISSON_ARRAY;
                    goto fail;
                }
                break;
            case PSID_PRIORITY_SSP:
                if(permissions->u.psid_priority_ssp_array.len > MAX_PERMISSIONS_LENGTH){
                    ret = TOO_MANY_ENTRIES_IN_PERMISSON_ARRAY;
                    goto fail;
                }
                break;
            case INHERITED_NOT_FOUND:
                wave_printf("权限类型为继承");
                break;
            default:
                wave_error_printf("错误的permission type");
                ret = FAILURE;
                goto fail;
        }
    }

    if(scope != NULL){
        switch(scope->region_type){
            case CIRCLE:
                break;
            case RECTANGLE:
                if(scope->u.rectangular_region.len > MAX_RECTANGLES_ENTRIES_NUM){
                    ret = TOO_MANY_ENTRIES_IN_RECTANGULAR_GEOGRAPHIC_SCOPE;
                    goto fail;
                }
                break;
            case POLYGON:
                if(scope->u.polygonal_region.len > MAX_POLYGON_VERTICES_ENTRIES_NUM){
                    ret = TOO_MANY_ENTRIES_IN_POLYGONAL_GEOGRAPHIC_SCOPE;
                    goto fail;
                }
            case NONE:
                break;
            case FROM_ISSUER:
                wave_printf("region type为继承");
                break;
            default:
                wave_error_printf("错误的region type");
                ret = UNSUPPORTED_REGION_TYPE_IN_CERTIFICATE;
                goto fail;
        }
    }
    if(permissions != NULL && scope != NULL){
        if(permissions->type != INHERITED_NOT_FOUND && scope->region_type != FROM_ISSUER)
            goto fail;        
    }
    else if(permissions != NULL){
        if(permissions->type != INHERITED_NOT_FOUND)
            goto fail;
    }
    else if(scope != NULL){
        if(scope->region_type != FROM_ISSUER)
            goto fail;
    }
    else
        goto fail;
    if(trust_anchor){
        ret = CERTIFICATE_BADLY_FORMED;
        goto fail;
    }

    if(hashided8_2_string(&cert_info.cert->unsigned_certificate.u.no_root_ca.signer_id, &signer_id)){
        wave_error_printf("hash to string fail!");
        goto fail;
    }
    
    struct cme_permissions *p;
    geographic_region *s;
    if(permissions == NULL)
        p = NULL;
    else{
        if(permissions->type == INHERITED_NOT_FOUND)
            p = NULL;
        else
            p = permissions;
    }
    if(scope == NULL){
        s = NULL;
    }
    else{
        if(scope->region_type == FROM_ISSUER)
            s = NULL;
        else
            s = scope;
    }

    ret = cme_certificate_info_request(sdb, ID_HASHEDID8, &signer_id, NULL, p, s, NULL, NULL, NULL, NULL);

fail:
    certificate_free(&cert_decoded);
    cert_info_free(&cert_info);
    string_free(&signer_id);
    p = NULL;
    s = NULL;

    return ret;
}

result cme_add_trust_anchor(struct sec_db* sdb,certificate *cert){
    result res = SUCCESS;
    struct cert_info *cert_info = NULL;
    struct certificate *mcert = NULL;
    struct cme_db *cdb;
    string identifier;
    struct verified_array verifieds;
    int i;

    INIT(identifier);
    INIT(verifieds);

    if(cert->version_and_type != EXPLICT){
        wave_error_printf("证书是不是现式的 %s %d",__FILE__,__LINE__);
        res = FAILURE;
        goto end; 
    }
    if( is_certificate_revoked(sdb,cert) != false){
        wave_error_printf("证书被吊销了  %s %d",__FILE__,__LINE__);
        res = FAILURE;
        goto end;
    }
    if(cert->unsigned_certificate.holder_type == ROOT_CA){
       //?????????????? 这里要校验哈是否是自己签发自己对了的
    }
    if( (cert_info = (struct cert_info*)malloc(sizeof(struct cert_info))) == NULL){
        wave_malloc_error();
        res = FAILURE;
        goto end;
    }
    INIT(*cert_info);
    if( (mcert = (struct certificate*)malloc(sizeof(certificate))) == NULL){
        wave_malloc_error();
        res = FAILURE;
        goto end;
    }
    INIT(*mcert);
    if( certificate_cpy(mcert,cert)){
        res = FAILURE;
        goto end;
    }

    if( cert_info_init(sdb,cert_info,mcert)){
        res =FAILURE;
        goto end;
    }
    cdb = &sdb->cme_db;
    lock_wrlock(&cdb->lock);
    cdb->certs = cert_info_insert(cdb->certs,cert_info);
    lock_unlock(&cdb->lock);
    goto end;
end:
    string_free(&identifier);
    verified_array_free(&verifieds);

    if(res != SUCCESS && cert_info != NULL){
        if(cert_info->cert != NULL)
            mcert = NULL;
        cert_info_free(cert_info);
        free(cert_info);
    }
    if( res != SUCCESS && mcert != NULL){
        certificate_free(mcert);
        free(mcert);
    }
    return res;    
}
result cme_add_certificate(struct sec_db* sdb,certificate* cert,bool verified){
    result res = SUCCESS;
    struct cert_info *cinfo = NULL;
    struct cme_db *cdb;
    certificate *mycert = NULL;
    
    if( is_certificate_revoked(sdb,cert) == true){
        res = FAILURE;
        goto end;
    }
    cdb = &sdb->cme_db;
    if( (mycert = (certificate*)malloc(sizeof(certificate))) == NULL ||
            (cinfo = (struct cert_info*)malloc(sizeof(struct cert_info))) == NULL){
        wave_malloc_error();
        res = FAILURE;
        goto end;
    }
    INIT(*cinfo);
    INIT(*mycert);

    if(certificate_cpy(mycert,cert)){
        res = FAILURE;
        goto end;
    }
    if(cert_info_init(sdb,cinfo,mycert)){
        res = FAILURE;
        goto end;
    }
    cinfo->verified = verified;
    lock_wrlock(&cdb->lock);
    cdb->certs = cert_info_insert(cdb->certs,cinfo);
    lock_unlock(&cdb->lock);
    goto end;
end:
    if(res != SUCCESS){
        if(cinfo != NULL){
            if(cinfo->cert != NULL)
                mycert = NULL;
            cert_info_free(cinfo);
            free(cinfo);
        }
        if(mycert != NULL){
            certificate_free(mycert);
            free(mycert);
        }
    }
    return res;
}
void cme_delete_cmh(struct sec_db *sdb,cmh cmh){
    result res = SUCCESS;
    struct cme_db *cdb;
    struct list_head *head;
    struct cmh_chain *cmh_init_temp,*cmh_chain_temp,*new_cmh_node=NULL;
    struct cmh_keypaired *cmh_keys_temp;
    struct cmh_key_cert* cmh_key_cert_temp;
    struct cert_info *cinfo;

    if( (new_cmh_node = (struct cmh_chain*)malloc(sizeof(struct cmh_chain))) == NULL){
        wave_malloc_error();
        res = FAILURE;
        goto end;
    }
    INIT(*new_cmh_node);
    cdb = &sdb->cme_db;
    lock_wrlock(&cdb->lock);
    head = &cdb->cmhs.alloc_cmhs.cmh_init.list;
    list_for_each_entry(cmh_init_temp,head,list){
        if(cmh_init_temp->cmh == cmh){
            list_del(&cmh_init_temp->list);
            free(cmh_init_temp);
            goto insert; 
        }
        if(cmh_init_temp->cmh > cmh){
            break;
        }
    }

    head = &cdb->cmhs.alloc_cmhs.cmh_keys.list;
    list_for_each_entry(cmh_keys_temp,head,list){
        if(cmh_keys_temp->cmh == cmh){
            list_del(&cmh_keys_temp->list);
            cmh_keypaired_free(cmh_keys_temp);
            free(cmh_keys_temp);
            goto insert;
        }
        if(cmh_keys_temp->cmh > cmh)
            break;
    }

    cmh_key_cert_temp = ckc_find(cdb->cmhs.alloc_cmhs.cmh_key_cert,&cmh);
    if(cmh_key_cert_temp == NULL){
        lock_unlock(&cdb->lock);
        goto end;
    }
    cdb->cmhs.alloc_cmhs.cmh_key_cert = ckc_delete(cdb->cmhs.alloc_cmhs.cmh_key_cert,cmh_key_cert_temp);
    cinfo = cmh_key_cert_temp->cert_info;
    cmh_key_cert_free(cmh_key_cert_temp);
    if(cinfo != NULL){
        cdb->certs = cert_info_delete(cdb->certs,cinfo);
        cinfo->cert = NULL;
        cert_info_free(cinfo);
        free(cinfo);
    }
    goto insert;

insert:
    head = &cdb->cmhs.cmh_chain.list;
    new_cmh_node->cmh = cmh;
    list_for_each_entry(cmh_chain_temp,head,list){
        if(cmh_chain_temp->cmh > cmh){
            break;
        }
    }
    list_add_tail(&new_cmh_node->list,&cmh_chain_temp->list);
    return;
end:
    if(new_cmh_node != NULL)
        free(new_cmh_node);
    return;

}
result cme_add_certificate_revocation(struct sec_db* sdb,certid10* identifier,hashedid8* ca_id,crl_series series,time64 expiry){
    struct cme_db *cdb;
    struct cert_info *cinfo;
    struct list_head *series_head,*ca_head,*rev_head;
    struct crl_head* crl_series_temp;
    struct crl_ca_id* crl_ca_temp;
    struct revoked_certs *rev_cert,*rev_cert_temp;
    int cmp;
    cdb = &sdb->cme_db;
    lock_wrlock(&cdb->lock);
    cinfo = cert_info_find(cdb->certs,&identifier);
    if(cinfo != NULL){
        if(cinfo->cert->unsigned_certificate.crl_series != series){
            wave_printf(MSG_WARNING,"certid10 相等 但是serires不相等 %s %d",__FILE__,__LINE__);
            lock_unlock(&cdb->lock);
            return INVALID_INPUT;
        }
        if(cinfo->cert->unsigned_certificate.holder_type == ROOT_CA ||
                hashedid8_equal(ca_id,&cinfo->cert->unsigned_certificate.u.no_root_ca.signer_id) == false){
            wave_printf(MSG_WARNING,"ca id 不相等 %s %d",__FILE__,__LINE__);
            lock_unlock(&cdb->lock);
            return INVALID_INPUT;
        }
        cinfo->revoked = true;
        if(expiry != 0){
            cinfo->expriry = expiry; 
        }
    }
    //并将这个信息保存在链表中
    if( (rev_cert = (struct revoked_certs*)malloc(sizeof(struct revoked_certs))) == NULL){
        wave_malloc_error();
        return FAILURE;
    }
    INIT(*rev_cert);
    //这里是有bug的，如果不现有这个相应的crl下面将找不到，但是我们认为别人受到了crl肯定是先调用add_crlinfo,在调用本函数
    certid10_cpy(&rev_cert->certid,identifier);
    series_head = &cdb->crls.list;
    list_for_each_entry(crl_series_temp,series_head,list){
        if(crl_series_temp->crl_series == series){
            ca_head = &crl_series_temp->ca_id_list.list;
            list_for_each_entry(crl_ca_temp,ca_head,list){
                if(hashedid8_equal(&crl_ca_temp->ca_id,ca_id)){
                    rev_head = &crl_ca_temp->revoked_certs.list;
                    list_for_each_entry(rev_cert_temp,rev_head,list){
                        cmp = certid10_cmp(&rev_cert_temp->certid,&rev_cert->certid);
                        if(cmp > 0)
                            break;
                        else if(cmp == 0){
                            lock_unlock(&cdb->lock);
                            return SUCCESS;
                        }
                    }
                    list_add_tail(&rev_cert->list,&rev_cert_temp->list);
                    break;
                }
            }
        }
    }
    lock_unlock(&cdb->lock);
    return SUCCESS;

}

void cme_add_crlinfo(struct sec_db* sdb,crl_type crl_type,crl_series series,hashedid8* ca_id,u32 serial_number,
                            time32 start_period,time32 issue_date,time32 next_crl_time){
    struct cme_db *cdb;
    struct list_head *series_head,*ca_head,*serial_head;
    struct crl_head *series_temp,*new_series = NULL;
    struct crl_ca_id *ca_temp,*new_ca = NULL;
    struct crl_serial_number *serial_temp,*new_serial = NULL;
    int cmp;
    result res = SUCCESS;

    cdb = &sdb->cme_db;

    lock_wrlock(&cdb->lock);
    series_head = &cdb->crls.list;
    list_for_each_entry(series_temp,series_head,list){
        if(series_temp->crl_series == series){
            ca_head = &series_temp->ca_id_list.list;
            list_for_each_entry(ca_temp,ca_head,list){
                cmp = hashedid8_cmp(&ca_temp->ca_id,ca_id);
                if(cmp > 0)
                    break;
                if(cmp == 0){
                    serial_head = &ca_temp->crl_info_list.list;
                    list_for_each_entry(serial_temp,serial_head,list){
                        if(serial_temp->serial_number == serial_number){
                            serial_temp->start_period = start_period;
                            serial_temp->issue_date = issue_date;
                            serial_temp->next_crl_time = next_crl_time;
                            serial_temp->type = crl_type;
                            lock_unlock(&cdb->lock);
                            return;
                        }
                        if(serial_temp->serial_number > serial_number){
                            break;
                        }
                    }
                    if( (new_serial = (struct crl_serial_number*)malloc(sizeof(struct crl_serial_number))) == NULL){
                        lock_unlock(&cdb->lock);
                        wave_malloc_error();
                        goto end;
                    }
                    new_serial->issue_date = issue_date;
                    new_serial->next_crl_time = next_crl_time;
                    new_serial->serial_number = serial_number;
                    new_serial->start_period = start_period;
                    new_serial->type = crl_type;
    
                    list_add_tail(&new_serial->list,&serial_temp->list);
                    lock_unlock(&cdb->lock);
                    return ;

                }
            }
            if( ( new_ca = (struct crl_ca_id*)malloc(sizeof(struct crl_ca_id))) == NULL ||
                (new_serial = (struct crl_serial_number*)malloc(sizeof(struct crl_serial_number))) == NULL){
                    lock_unlock(&cdb->lock);
                    wave_malloc_error();
                    goto end;
            }
            new_serial->issue_date = issue_date;
            new_serial->next_crl_time = next_crl_time;
            new_serial->serial_number = serial_number;
            new_serial->start_period = start_period;
            new_serial->type = crl_type;
    
            INIT_LIST_HEAD(&new_ca->crl_info_list.list);
            list_add_tail(&new_serial->list,&new_ca->crl_info_list.list);
            hashedid8_cpy(&new_ca->ca_id,ca_id);

            list_add_tail(&new_ca->list,&ca_temp->list);
            lock_unlock(&cdb->lock);
            return;
        }
        else if(series_temp->crl_series > series){
            break;
        }
    }
    if( ( new_series = (struct crl_head*)malloc(sizeof(struct crl_head))) == NULL ||
            ( new_ca = (struct crl_ca_id*)malloc(sizeof(struct crl_ca_id))) == NULL ||
            (new_serial = (struct crl_serial_number*)malloc(sizeof(struct crl_serial_number))) == NULL){
        lock_unlock(&cdb->lock);
        wave_malloc_error();
        goto end;
    }
    new_serial->issue_date = issue_date;
    new_serial->next_crl_time = next_crl_time;
    new_serial->serial_number = serial_number;
    new_serial->start_period = start_period;
    new_serial->type = crl_type;
    
    INIT_LIST_HEAD(&new_ca->crl_info_list.list);
    list_add_tail(&new_serial->list,&new_ca->crl_info_list.list);
    hashedid8_cpy(&new_ca->ca_id,ca_id);

    INIT_LIST_HEAD(&new_series->ca_id_list.list);
    list_add_tail(&new_ca->list,&new_series->ca_id_list.list);
    new_series->crl_series = series;
    
    list_add_tail(&new_series->list,&series_temp->list);
    lock_unlock(&cdb->lock);
    return ;
end:
    if(new_series != NULL){
        free(new_series);
    }
    if(new_ca != NULL){
        free(new_ca);
    }
    if( new_serial != NULL){
        free(new_serial);
    }
    return;
}

result cme_get_crlinfo(struct sec_db* sdb,crl_series series,hashedid8* ca_id,u32 serial_number,
        
                        crl_type *type,time32 *start_time,time32 *issue_date,time32 *next_crl_time){
    struct cme_db *cdb;
    struct list_head *series_head,*ca_head,*serial_head;
    struct crl_head *series_temp;
    struct crl_ca_id *ca_temp;
    struct crl_serial_number *serial_temp;
    result res = SUCCESS;
    int cmp ;

    lock_rdlock(&cdb->lock);
    series_head = &cdb->crls.list;
    list_for_each_entry(series_temp,series_head,list){
        if(series_temp->crl_series > series){
            lock_unlock(&cdb->lock);
            return FAILURE;
        }
        if(series_temp->crl_series == series){
            ca_head = &series_temp->ca_id_list.list;
            list_for_each_entry(ca_temp,ca_head,list){
                cmp = hashedid8_cmp(&ca_temp->ca_id,ca_id);
                if(cmp > 0){
                    lock_unlock(&cdb->lock);
                    return FAILURE;
                }
                if(cmp == 0){
                    serial_head = &ca_temp->crl_info_list.list;
                    list_for_each_entry(serial_temp,serial_head,list){
                        if(serial_temp->serial_number == serial_number){
                            if(type != NULL){
                                *type = serial_temp->type;
                            }
                            if(start_time != NULL)
                                *start_time = serial_temp->start_period;
                            if(issue_date != NULL)
                                *issue_date = serial_temp->issue_date;
                            if(next_crl_time != NULL)
                                *next_crl_time = serial_temp->next_crl_time;
                            lock_unlock(&cdb->lock);
                            return SUCCESS;
                        }
                        else if(serial_temp->serial_number > serial_number){
                            lock_unlock(&cdb->lock);
                            return FAILURE;
                        }
                    }
                }
            }
        }
    }
    lock_unlock(&cdb->lock);
    return FAILURE;

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
                struct time32_array *last_crl_times_array,
                struct time32_array *next_crl_times_array,
                struct verified_array *verified_array){
    result ret = FAILURE;
    struct certificate *certificate = NULL;
    bool trust_anchor;
    int i = 0, j = 0;
    string sign_id;
    string cert_encoded;
    string hash8;

    INIT(sign_id);
    INIT(hash8);
    INIT(cert_encoded);

    if(certificate_chain != NULL){
        if(certificate_chain->certs != NULL){
            wave_error_printf("证书链中buf已经被填充");
            ret = FAILURE;
            goto fail;
        }
        certificate_chain->certs = malloc(sizeof(struct certificate)*max_chain_len);
        if(!certificate_chain->certs){
            wave_error_printf("内存分配失败");
            ret = FAILURE;
            goto fail;
        }
        memset(certificate_chain->certs, 0, sizeof(struct certificate)*max_chain_len);
        certificate_chain->len = 0;
    }

    if(permissions_array != NULL){
        if(permissions_array->cme_permissions != NULL){
            wave_error_printf("permissions中buf已经被填充");
            ret = FAILURE;
            goto fail;
        }
        permissions_array->cme_permissions = malloc(sizeof(struct cme_permissions)*max_chain_len);
        if(!permissions_array->cme_permissions){
            wave_error_printf("内存分配失败");
            ret = FAILURE;
            goto fail;
        }
        memset(permissions_array->cme_permissions, 0, sizeof(struct cme_permissions)*max_chain_len);
        permissions_array->len = 0;
    }

    if(regions != NULL){
        if(regions->regions != NULL){
            wave_error_printf("regions的buf已经被填充");
            ret = FAILURE;
            goto fail;
        }
        regions->regions = malloc(sizeof(struct geographic_region)*max_chain_len);
        if(!regions->regions){
            wave_error_printf("内存分配失败");
            ret = FAILURE;
            goto fail;
        }
        memset(regions->regions, 0, sizeof(struct geographic_region)*max_chain_len);
        regions->len = 0;
    }

    if(last_crl_times_array != NULL){
        if(last_crl_times_array->times != NULL){
            wave_error_printf("last crl中的buf已经被填充");
            ret = FAILURE;
            goto fail;
        }
        last_crl_times_array->times = malloc(sizeof(time32)*max_chain_len);
        if(!last_crl_times_array->times){
            wave_error_printf("内存分配失败");
            ret = FAILURE;
            goto fail;
        }
        memset(last_crl_times_array->times, 0, sizeof(time32)*max_chain_len);
        last_crl_times_array->times = 0;
    }

    if(next_crl_times_array != NULL){
        if(next_crl_times_array->times != NULL){
            wave_error_printf("next crl的buf已经被填充");
            ret = FAILURE;
            goto fail;
        }
        next_crl_times_array->times = malloc(sizeof(time32)*max_chain_len);
        if(!next_crl_times_array->times){
            wave_error_printf("内存分配失败");
            ret = FAILURE;
            goto fail;
        }
        memset(next_crl_times_array->times, 0, sizeof(time32)*max_chain_len);
        next_crl_times_array->len = 0;
    }

    if(verified_array != NULL){
        if(verified_array->verified != NULL){
            wave_error_printf("verified中的buf已经被填充");
            ret = FAILURE;
            goto fail;
        }
        verified_array->verified = malloc(sizeof(bool)*max_chain_len);
        if(!verified_array->verified){
            wave_error_printf("内存分配失败");
            ret = FAILURE;
            goto fail;
        }
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
        if(sign_id.buf != NULL){
            free(sign_id.buf);
            sign_id.buf = NULL;
        }
        sign_id.buf = malloc(sizeof(u8)*8);
        if(sign_id.buf == NULL){
            wave_error_printf("内存分配失败!");
            ret = FAILURE;
            goto fail;
        }
        memcpy(sign_id.buf, certificate->unsigned_certificate.u.no_root_ca.signer_id.hashedid8, 8);
        certificate = NULL;
    }

    string_free(&cert_encoded);
    INIT(cert_encoded);

    if(certificate == NULL)
        ret = cme_certificate_info_request(sdb, ID_HASHEDID8, &sign_id, &cert_encoded, &(permissions_array->cme_permissions[i]), 
                &(regions->regions[i]), &(last_crl_times_array->times[i]), &(next_crl_times_array->times[i]), 
                &trust_anchor, &(verified_array->verified[i]));
    else{
        certificate_2_string(certificate, &cert_encoded);
        ret = cme_certificate_info_request(sdb, ID_CERTIFICATE, &cert_encoded, &cert_encoded, &(permissions_array->cme_permissions[i]), 
                &(regions->regions[i]), &(last_crl_times_array->times[i]), &(next_crl_times_array->times[i]), 
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
            string_free(&hash8);
            INIT(hash8);
            if(certificate_2_hash8(&certificates->certs[i],&hash8)){
                wave_error_printf("证书转hash8失败");
                ret = FAILURE;
                goto fail;
            }
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


/*****************************************证书的一些操作的实现*************/

int certificate_2_hash8(struct certificate *cert,string *hash8){

    if(hash8 == NULL || hash8->buf != NULL){
        wave_error_printf("参数错误");
    }
    string c,hashed;
    INIT(c);
    INIT(hashed);
    if( certificate_2_string(cert,&c) ){
        goto fail;
    }
    if( crypto_HASH256(&c,&hashed) ){
        goto fail;
    }
    hash8->buf = (u8*)malloc(8);
    if(hash8->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    //什么是低字节，这个地方是低字节嘛
    memcpy(hash8->buf,hashed.buf+hashed.len-8,8);
    wave_printf(MSG_DEBUG,"证书hash出来的低八字杰为：HASHEDID8_FORMAT",hash8.buf[0],hash8.buf[1],hash8.buf[2],hash8.buf[3],
                hash8.buf[4],hash8.buf[5],hash8.buf[6],hash8.buf[7]);
    string_free(&c);
    string_free(&hashed);
    return 0;
fail:
    string_free(&c);
    string_free(&hashed);
    return -1;
}

int certificate_2_hashedid8(struct certificate *cert,hashedid8* hash8){

    if(hash8 == NULL ){
        wave_error_printf("参数错误");
    }
    string c,hashed;
    INIT(c);
    INIT(hashed);
    if( certificate_2_string(cert,&c) ){
        goto fail;
    }
    if( crypto_HASH256(&c,&hashed) ){
        goto fail;
    }
    //什么是低字节，这个地方是低字节嘛
    memcpy(hash8->hashedid8,hashed.buf+hashed.len-8,8);
    string_free(&c);
    string_free(&hashed);
    return 0;
fail:
    string_free(&c);
    string_free(&hashed);
    return -1;
}
int certificate_2_certid10(struct certificate *cert,certid10* certid){
    if(certid == NULL ){
        wave_error_printf("参数错误");
    }
    string c,hashed;
    INIT(c);
    INIT(hashed);
    if( certificate_2_string(cert,&c) ){
        goto fail;
    }
    if( crypto_HASH256(&c,&hashed) ){
        goto fail;
    }
    //什么是低字节，这个地方是低字节嘛
    memcpy(certid->certid10,hashed.buf+hashed.len-10,10);
    string_free(&c);
    string_free(&hashed);
    return 0;
fail:
    string_free(&c);
    string_free(&hashed);
    return -1;
}
int certificate_get_elliptic_curve_point(certificate* cert,elliptic_curve_point* point){
    if(point->x.buf != NULL || point->u.y.buf != NULL){
        wave_error_printf("出现野指针 %s %d",__FILE__,__LINE__);
        return -1;
    }
    pk_algorithm algorithm;
    
    switch(point->type){
        case 2:
            if(cert->unsigned_certificate.holder_type == ROOT_CA){
                 algorithm = cert->unsigned_certificate.version_and_type.verification_key.algorithm;
            }
            else{
                algorithm = cert->unsigned_certificate.u.no_root_ca.signature_alg;
            }
            if(algorithm != ECDSA_NISTP224_WITH_SHA224 && algorithm != ECDSA_NISTP256_WITH_SHA256){
                wave_error_printf("这里等于了一个不应该有的指  %s %d",__FILE__,__LINE__);
                return -1;
            }
            elliptic_curve_point_cpy(point,&cert->u.signature.u.ecdsa_signature.r);     
            break;
        case 3:
           elliptic_curve_point_cpy(point,&cert->u.reconstruction_value);   
           break;
        default:
           wave_error_printf("这里不可能出现其他的指的 %s %d",__FILE__,__LINE__);
           return -1;
    }
    return 0;

}
