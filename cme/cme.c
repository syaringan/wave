#include "cme.h"
#include "cme_db.h"
#include "data/data_handle.h"
#include "sec/sec_db.h"
#include <stdlib.h>
#include <time.h>
#define INIT(n) memset(&n,0,sizeof(n))
#define MAX_PERMISSIONS_LENGTH 8
#define MAX_RECTANGLES_ENTRIES_NUM 12
#define MAX_POLYGON_VERTICES_ENTRIES_NUM 12

#define IMPLICT 3
#define EXPLICT 2

void time32_array_free(struct time32_array *ptr){
    if(ptr == NULL)
        return ;
    free(ptr->times);
    ptr->times = NULL;
    ptr->len = 0;
}
void cme_permissions_free(struct cme_permissions* permissions){
    switch(permissions->type){
        case PSID:
            if(permissions->u.psid_array.buf == NULL)
                return ;
            free(permissions->u.psid_array.buf);
            permissions->u.psid_array.buf = NULL;
            permissions->u.psid_array.len = 0;
            break;
        case PSID_PRIORITY:
            if(permissions->u.psid_priority_array.buf == NULL)
                return;
            free(permissions->u.psid_priority_array.buf);
            permissions->u.psid_priority_array.len = 0;
            permissions->u.psid_priority_array.buf = NULL;
            break;
        case PSID_SSP:
            if(permissions->u.psid_ssp_array.buf == NULL)
                return ;
            free( permissions->u.psid_ssp_array.buf);
            permissions->u.psid_ssp_array.buf == NULL;
            permissions->u.psid_ssp_array.len = 0;
            break;
        case PSID_PRIORITY_SSP:
            if( permissions->u.psid_priority_ssp_array.buf == NULL)
                return ;
            free( permissions->u.psid_priority_ssp_array.buf);
            permissions->u.psid_priority_ssp_array.len = 0;
            permissions->u.psid_priority_ssp_array.buf = NULL;
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
        wave_error_printf("cmh为空 %s %d",__FILE__,__LINE__);
        return FAILURE;
    }
    

    node = list_entry(head->next,struct cmh_chain,list);
    list_del(&node->list);
    cme_cmh_init_insert(cdb,node);
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
            if(crypto_ECDSA_224_get_key(&mprk,pub_key_x,pub_key_y)){
                res = FAILURE;
                goto end;
            }
            break;
        case ECDSA_NISTP256_WITH_SHA256:
            if(crypto_ECDSA_256_get_key(&mprk,pub_key_x,pub_key_y)){
                res = FAILURE;
                goto end;
            }
            break;
        case ECIES_NISTP256:
            if( crypto_ECIES_get_key(&mprk,pub_key_x,pub_key_y)){
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
        wave_printf(MSG_WARNING,"这里我觉得不应该是root_ca的 %s %d",__FILE__,__LINE__);
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
                        if(last_crl_time != NULL)
                            *last_crl_time = 0;
                        if(next_crl_time != NULL)
                            *next_crl_time = 0;
                        return SUCCESS; 
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
    if(last_crl_time != NULL)
        *last_crl_time = 0;
    if(next_crl_time != NULL)
        *next_crl_time = 0;
    return SUCCESS; 
}
static void del_certificate_by_certid10(struct sec_db* sdb,certid10* certid){
    struct cme_db *cdb;
    struct cert_info *cinfo;
    struct cert_info_cmp cinfo_cmp;

    cdb = &sdb->cme_db;
    cinfo_cmp.type = ID_CERTID10;
    certid10_cpy(&cinfo_cmp.u.certid10,certid);
    lock_wrlock(&cdb->lock);
    cinfo = cert_info_find(cdb->certs,&cinfo_cmp);
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
/**
 * 如果transfor为ＮＵＬＬ表示不做私钥转换
 */
result cme_store_cert(struct sec_db* sdb,  cmh cmh,
                          certificate* cert,
                          string* transfor){

    struct list_head *cmh_keys_head,*cmh_key_cert_head;
    struct cmh_keypaired *cmh_keys_node;
    struct cmh_key_cert *root,*new_key_cert_node = NULL;
    struct certificate* mcert = NULL;
    struct cert_info* certinfo = NULL;
    struct cme_db *cdb;
    string cert_string,hash256;

    cdb = &sdb->cme_db;
    INIT(cert_string);
    INIT(hash256);
   
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
    if(transfor != NULL){
        if(cert->version_and_type != 3){
            lock_unlock(&cdb->lock);
            wave_error_printf("不是隐士证书，你怎么要做转换 %s %d",__FILE__,__LINE__);
            goto fail;
        }

        if(certificate_2_string(cert,&cert_string) ||
                crypto_HASH_256(&cert_string,&hash256)){
            lock_unlock(&cdb->lock);
            goto fail;
        }
        if(cmh_keys_node->private_key.len == 32){
            if(crypto_cert_reception_SHA256(&cmh_keys_node->private_key,&hash256,transfor,&new_key_cert_node->private_key)){
                lock_unlock(&cdb->lock);
                goto fail;
            }
        }
        else if(cmh_keys_node->private_key.len == 28){
            if(crypto_cert_reception_SHA224(&cmh_keys_node->private_key,&hash256,transfor,&new_key_cert_node->private_key)){
                lock_unlock(&cdb->lock);
                goto fail;
            }
        }
        else{
            wave_error_printf("钥匙长度怎么会是其他指 %s %d",__FILE__,__LINE__);
            goto fail;
        }
    }
    else{
        string_cpy(&new_key_cert_node->private_key,&cmh_keys_node->private_key);
    }


    cdb->cmhs.alloc_cmhs.cmh_key_cert = ckc_insert(root,new_key_cert_node);
    cdb->certs = cert_info_insert(cdb->certs,certinfo);
    lock_unlock(&cdb->lock);
    list_del(&cmh_keys_node->list);
    cmh_keypaired_free(cmh_keys_node);
    free(cmh_keys_node);
    string_free(&cert_string);
    string_free(&hash256);
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
    string_free(&cert_string);
    string_free(&hash256);
    return FAILURE;
}

result cme_store_cert_key(struct sec_db* sdb, cmh cmh, certificate* cert,
                              string* pri_key){
    struct cert_info *certinfo= NULL,root;
    struct certificate* mcert = NULL; 
    struct cme_db* cdb;
    struct list_head *head;
    struct cmh_chain* cmh_init;
    struct cmh_key_cert *key_cert = NULL;
    cdb = &sdb->cme_db;
    
    lock_wrlock(&cdb->lock);
    head = &cdb->cmhs.alloc_cmhs.cmh_init.list;
    list_for_each_entry(cmh_init,head,list){
        if(cmh_init->cmh == cmh){
            break;
        }
        if(cmh_init->cmh  > cmh){
            wave_error_printf("没有找到这个cmh %s %d",__FILE__,__LINE__);
            lock_unlock(&cdb->lock);
            goto fail;
        }
    }
    if(&cmh_init->list == head){
        wave_error_printf("没有找到这个cmh %s %d",__FILE__,__LINE__);
        lock_unlock(&cdb->lock);
        goto fail;
    }
    list_del(&cmh_init->list);
    free(cmh_init);


    mcert = (struct certificate*)malloc(sizeof(struct certificate));
    if(mcert == NULL){
        wave_error_printf("内存分配失败");
        lock_unlock(&cdb->lock);
        goto fail;
    }
    INIT(*mcert);
    certinfo = (struct cert_info*)malloc(sizeof(struct cert_info));
    if(certinfo == NULL){
        wave_error_printf("内存分配失败");
        lock_unlock(&cdb->lock);
        goto fail;
    }
    INIT(*certinfo);
    key_cert = (struct cmh_key_cert*)malloc(sizeof(struct cmh_key_cert));
    if(key_cert == NULL){
        wave_error_printf("内存分配失败");
        lock_unlock(&cdb->lock);
        goto fail;
    }
    INIT(*key_cert);

    certificate_cpy(mcert,cert);
    cert_info_init(sdb,certinfo,mcert);
    cdb->certs = cert_info_insert(cdb->certs,certinfo);
    certinfo->key_cert = key_cert;

    key_cert->cert = mcert;
    ckc_init_rb(key_cert);
    key_cert->cert_info = certinfo;
    key_cert->cmh = cmh;
    string_cpy(&key_cert->private_key,pri_key);
    cdb->cmhs.alloc_cmhs.cmh_key_cert = ckc_insert(cdb->cmhs.alloc_cmhs.cmh_key_cert,key_cert);
    lock_unlock(&cdb->lock);
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
    if(key_cert != NULL){
        key_cert->cert = NULL;
        key_cert->cert_info = NULL;
        free(key_cert);
    }
    return FAILURE;
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
    struct cert_info *cert_info;
    time32 m_next_crl_time;
    time32 m_last_crl_time;
    string signer_id;

    INIT(signer_id);
    INIT(cert_decoded);

    if(get_cert_info_by_certid(sdb, type, identifier, &cert_info)){
        ret = CERTIFICATE_NOT_FOUND;
        if(type == ID_CERTIFICATE){
            if(next_crl_time != NULL){
                if(string_2_certificate(identifier, &cert_decoded) <= 0){
                    wave_error_printf("证书解码失败!");
                    ret = FAILURE;
                    goto fail;
                }
                if( get_crl_time_by_certificate(sdb,&cert_decoded,NULL,next_crl_time)){
                    ret = FAILURE;
                    goto fail;
                }
            }
        }
        goto fail;
    }

    if(!cert_info->revoked){
        ret = CERTIFICATE_REVOKED;
        goto fail;
    }

    if(get_crl_time_by_certificate(sdb, cert_info->cert, &m_last_crl_time, &m_next_crl_time)){
        wave_error_printf("获取crl失败");
        ret = FAILURE;
        goto fail;
    }
    if(m_next_crl_time < time(NULL) || cert_info->expriry / US_TO_S < time(NULL)){
        ret = CERTIFICATE_NOT_TRUSTED;
        goto fail;
    }
    ret = FOUND;
    if(verified != NULL){
        *verified = cert_info->verified;
    }
    if(certificate != NULL){
        if(certificate_2_string(cert_info->cert, certificate)){
            wave_error_printf("证书编码失败");
            ret = FAILURE;
            goto fail;
        }
    }
    if(last_crl_time != NULL){
        *last_crl_time = m_last_crl_time;
    }
    if(next_crl_time != NULL){
        *next_crl_time = m_next_crl_time;
    }

    if(get_permission_from_certificate(cert_info->cert, permissions, scope)){
        wave_error_printf("提取证书权限失败");
        ret = FAILURE;
        goto fail;
    }
    if(trust_anchor != NULL){
        *trust_anchor = cert_info->trust_anchor;
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
                wave_error_printf("权限类型为继承");
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
                wave_printf(MSG_WARNING,"region type为继承");
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

    if(hashedid8_2_string(&cert_info->cert->unsigned_certificate.u.no_root_ca.signer_id, &signer_id)){
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
    struct cert_info_cmp cinfo_cmp;
    int cmp;
    cdb = &sdb->cme_db;
    cinfo_cmp.type = ID_CERTID10;
    certid10_cpy(&cinfo_cmp.u.certid10,identifier);
    lock_wrlock(&cdb->lock);
    cinfo = cert_info_find(cdb->certs,&cinfo_cmp);
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
result cme_reply_detection(struct sec_db* sdb,cme_lsis lsis,string* data){
   struct cme_db *cdb;
   struct list_head *head;
   struct cme_alloced_lsis *ptr;
   result res = SUCCESS;

   cdb = &sdb->cme_db;
   lock_wrlock(&cdb->lock);
   head = &cdb->lsises.alloced_lsis.list;
   list_for_each_entry(ptr,head,list){
        if(ptr->lsis == lsis){
            if( string_cmp(&ptr->data,data) == 0){
                res = REPLAY;
                lock_unlock(&cdb->lock);
                goto end;
            }
            else{
                string_free(&ptr->data);
                string_cpy(&ptr->data,data);
                res = NOT_REPLAY;
                lock_unlock(&cdb->lock);
                goto end;
            }
        }   
        else if(ptr->lsis > lsis){
            wave_error_printf("这里尽然没有这个lsis %s %d",__FILE__,__LINE__);
            res = FAILURE;
            lock_unlock(&cdb->lock);
            goto end;
        }
   }
   if(&ptr->list == head){
        wave_error_printf("这里尽然没有这个lsis %s %d",__FILE__,__LINE__);
        res = FAILURE;
        lock_unlock(&cdb->lock);
        goto end;
   }
   res = FAILURE;
   goto end;
end:
   return res;
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

