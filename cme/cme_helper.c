#include "cme_helper.h"
#include "data/data_handle.h"
#include "utils/debug.h"
#include <math.h>
#define INIT(n) memset(&n,sizeof(n),0)
int certificate_get_start_time(certificate* cert,time32 *start_time){
    if(cert->unsigned_certificate.expiration == 0){
        wave_printf(MSG_WARNING,"这个证书没有过期时间");
        if(cert->unsigned_certificate.cf & USE_START_VALIDITY &&
                cert->unsigned_certificate.cf & LIFETIME_IS_DURATION == 0){
            if(start_time != NULL){
                *start_time = cert->unsigned_certificate.flags_content.start_validity;
            }
            return 0;
        }
        wave_error_printf("证书没有过期时间，只有证书持续时间或者都没有，不能推算出开始时间");
        return -1;
    }
    if(cert->unsigned_certificate.cf & USE_START_VALIDITY){
        if(cert->unsigned_certificate.cf & LIFETIME_IS_DURATION){
            if(start_time != NULL){
                *start_time = cert->unsigned_certificate.expiration - cert->unsigned_certificate.flags_content.lifetime;
            }
            return 0;
        }
        else{
            if(start_time != NULL){
                *start_time = cert->unsigned_certificate.flags_content.start_validity;
            }
            return 0;
        }
    }
    wave_error_printf("证书里面没有开始时间的相关消息");
    return -1;
}

int certificate_get_expired_time(struct sec_db* sdb,certificate* cert,time32 *expired_time){
    struct cme_db* cdb;
    struct cert_info *cinfo;
    certid10 certid;

    cdb = &sdb->cme_db;
    INIT(certid);

    if(certificate_2_certid10(cert,&certid)){
        return -1;
    }
    lock_wrlock(&cdb->lock);
    cinfo = cert_info_find(cdb->certs,&certid);
    if(cinfo == NULL){
        wave_error_printf("没有找到cinfo %s %d",__FILE__,__LINE__);
        lock_unlock(&cdb->lock);
        return -1;
    }
    if(expired_time != NULL)
        *expired_time = cinfo->expriry/US_TO_S;
    lock_unlock(&cdb->lock);
    return 0;
}
/*
 * 通过cmh找到对应的证书,成功返回0，失败返回-1,未测
 * */
int find_cert_by_cmh(struct sec_db *sdb, cmh cmh, struct certificate *cert){
    struct cmh_key_cert *p = NULL;
    if(cert != NULL){
        lock_rdlock(&sdb->cme_db.lock);
        p = ckc_find(sdb->cme_db.cmhs.alloc_cmhs.cmh_key_cert ,&cmh);
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

int find_keypaire_by_cmh(struct sec_db* sdb,cmh cmh,string* pubkey_x,string* pubkey_y,string* prikey,pk_algorithm* algorithm){
    if(pubkey_x == NULL || pubkey_x->buf != NULL ||
            pubkey_y == NULL || pubkey_y->buf != NULL ||
            prikey == NULL || prikey->buf != NULL){
        wave_error_printf("参数有问题 %s %d",__FILE__,__LINE__);
        return -1;
    }

    struct cme_db* cdb;
    struct list_head *head;
    struct cmh_keypaired *keys_node;
    cdb = &sdb->cme_db;
    lock_rdlock(&cdb->lock);
    head = &cdb->cmhs.alloc_cmhs.cmh_keys.list;
    list_for_each_entry(keys_node,head,list){
        if(keys_node->cmh > cmh){
            wave_error_printf("没有通过cmh找到对应的四要和公要 %s %d",__FILE__,__LINE__);
            lock_unlock(&cdb->lock);
            return -1;
        }
        if(keys_node->cmh == cmh){
            if(algorithm != NULL)
                *algorithm = keys_node->algorithm;
            if(pubkey_x != NULL){
                string_cpy(pubkey_x,&keys_node->public_key_x);
            }
            if(pubkey_y != NULL)
                string_cpy(pubkey_y,&keys_node->public_key_y);
            if(prikey != NULL)
                string_cpy(prikey,&keys_node->private_key);
            lock_unlock(&cdb->lock);
            return 0;

        }
    }
    wave_error_printf("没有通过cmh找到对应的四要和公要 %s %d",__FILE__,__LINE__);
    lock_unlock(&cdb->lock);
    return -1;
}

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
//如果在边上是算的，必须在内部
bool two_d_location_in_polygonal(two_d_location *td,two_d_location *polygonal,int len){
    int i,j,c=0;
    two_d_location *a,*b;
    for(i=0,j=len -1;i<len;j=i++){
        a = &polygonal[i];
        b = &polygonal[j];
        if( b->longitude == a->longitude && b->longitude == td->longitude && 
                (td->latitude < a->latitude) != (td->latitude < b->latitude) ){
            return true;
        }
        if( (td->longitude > a->longitude) != (td->longitude > b->longitude) ){
            if(  (td->latitude < (b->latitude - a->latitude)/(b->longitude - a->longitude) *(td->longitude - a->longitude) 
                    + a->latitude))
                c = !c;
            if( (td->latitude == (b->latitude - a->latitude)/(b->longitude - a->longitude) *(td->longitude - a->longitude) 
                    + a->latitude))
                return true;
        }
    }
    return c;
}
s64 direction(two_d_location* p1,two_d_location* p2, two_d_location* p3){
    return (p1->latitude-p2->latitude)*(p1->longitude - p3->longitude) - (p1->latitude - p3->latitude)*(p1->longitude - p2->longitude);
} 
//0代表只有一个交点，1代表有多个交点，即平行重合，但是肯定不再直线内，
//-1代表有多个交点，但是一定在直线内，-2 代表没有交点
int edge_intersect(two_d_location* p1,two_d_location* p2,two_d_location* p3,two_d_location* p4,double *x,double *y){
    s64 a1,b1,c1,a2,b2,c2;
    a1 = p2->longitude - p1->longitude;
    b1 = p1->latitude - p2->latitude;
    c1 = p2->latitude * p1->longitude - p2->longitude*p1->latitude;
    
    a2 = p4->longitude - p3->longitude;
    b2 = p3->latitude - p4->latitude;
    c2 = p4->latitude * p3->longitude - p4->longitude*p4->latitude;
    
    if(b1*a2 - b2* a1 == 0){
        if(a1 *p3->latitude + b1 *p3->longitude + c1 == 0){
            if( (p1->latitude < p3->latitude) != (p1->latitude < p4->latitude) &&
                    (p2->latitude < p3->latitude) != (p2->latitude < p4->latitude)){
                return -1;
            }
            return 1;
        }
        return -2;
    }

    *x = (c1*b2 - b1*c2)/(b1*a2 - b2 *a1);
    *y = (a1*c2 - c1*a2)/(b1*a2 - a1*b2);
    if( (*x<p1->latitude) != (*x<p2->latitude))
        return 0;
    return -2;
}
bool edge_in_polygonal(two_d_location *start,two_d_location *end,two_d_location* poly,int len){
    int count = 0,i,j,res;
    double x,y,prex,prey;
    two_d_location p;
    if(!two_d_location_in_polygonal(start,poly,len) || 
            !two_d_location_in_polygonal(end,poly,len))
        return false;
    for(i=0,j = len-1;i<len;j=i++){
        res = edge_intersect(start,end,poly+i,poly+j,&x,&y);
        if(res == -1)
            return true;
        if(res == 1)
            return false;
        if(res == -2)
            continue;
        if(count == 0){
            count = 1;
            prex = x;
            prey = y;
            continue;
        }
        p.latitude = (x+prex)/2;
        p.longitude = (y+prey)/2;
        prex = x;
        prey = y;
        if(!two_d_location_in_polygonal(&p,poly,len))
            return false;
    }
    return true;
}
//这里poly外面分配，四个空间
void rectangular_2_polygonal(rectangular_region* rec,two_d_location* poly){
    two_d_location *p;
    p = poly++;
    p->latitude = rec->north_west.latitude;
    p->longitude = rec->north_west.longitude;
    
    p = poly++;
    p->latitude = rec->north_west.latitude;
    p->longitude = rec->south_east.longitude;

    p = poly++;
    p->latitude = rec->south_east.latitude;
    p->longitude = rec->north_west.longitude;

    p = poly++;
    p->latitude = rec->south_east.latitude;
    p->longitude = rec->south_east.longitude;
}
bool circular_in_polygonal(circular_region* circle,two_d_location *poly,int len){
    two_d_location *center,*a,*b;
    u16 r;
    int i,j;
    double distance;
    center = &circle->center;
    r = circle->radius;
    if(!two_d_location_in_polygonal(center,poly,len))
        return false;
    for(i=0,j = len-1;i<len;j=i++){
        a = &poly[i];
        b = &poly[j];
        distance =fabs( (double)(b->longitude - a->longitude) * (center->latitude) +
                        (a->latitude - b->latitude) * (center->longitude) +
                        (b->latitude *a->longitude) - (a->latitude*b->longitude))
                    /(sqrt( (b->longitude-a->longitude) * (b->longitude -a->longitude) + 
                                (a->latitude - b->latitude) *(a->latitude - b->latitude) ));
        if(distance < r)
            return false;
    }
    return true;
}
bool polygnal_in_polygnal(two_d_location* polya,int a_len,two_d_location* poly,int len){
    int i,j;
    for(i=0,j=a_len-1;i<a_len;j=i++){
        if(!edge_in_polygonal(polya+i,polya+j,poly,len))
            return false;
    }
    return true;
}
bool rectangular_in_polygnal(rectangular_region *rec,two_d_location* poly,int len){
    two_d_location *p;
    bool res;
    p = malloc(sizeof(two_d_location) * 4);
    if(p == NULL){
        wave_malloc_error();
        return -1;
    }
    rectangular_2_polygonal(rec,p);
    res = polygnal_in_polygnal(p,4,poly,len);
    free(p);
    return res;
}
bool rectangulars_in_polygnal(rectangular_region* recs,int recs_len,two_d_location* poly,int len){
    int i;
    for(i=0;i<recs_len;i++){
        if(!rectangular_in_polygnal(recs+i,poly,len))
            return false;
    }
    return true;
}


bool circular_in_rectangular(circular_region *circle,rectangular_region* rec){
    two_d_location *p;
    bool res;
    p = malloc(sizeof(two_d_location) * 4);
    if(p == NULL){
        wave_malloc_error();
        return -1;
    }
    rectangular_2_polygonal(rec,p);
    res = circular_in_polygonal(circle,p,4);
    free(p);
    return res;
}
bool circular_in_rectangulars(circular_region* circle,rectangular_region* recs,int len){
    int i;
    for(i=0;i<len;i++){
        if(circular_in_rectangular(circle,recs+i))
            return true;
    }
    return false;
}
bool rectangular_in_rectangular(rectangular_region* reca,rectangular_region* recb){
    two_d_location *a,*b;
    bool res;
    a = malloc(sizeof(two_d_location) * 4);
    if(a == NULL){
        wave_malloc_error();
        return -1;
    }
    b = malloc(sizeof(two_d_location) * 4);
    if(b == NULL){
        free(a);
        wave_malloc_error();
        return -1;
    }
    rectangular_2_polygonal(reca,a);
    rectangular_2_polygonal(recb,b);
    res = polygnal_in_polygnal(a,4,b,4);
    free(a);
    free(b);
    return res; 
}
bool rectangular_in_rectangulars(rectangular_region* rec,rectangular_region* recs,int len){
    int i;
    for(i=0;i<len;i++){
        if(rectangular_in_rectangular(rec,recs+i))
            return true;
    }
    return false;
}
bool rectangulars_in_rectangulars(rectangular_region* recsa,int a_len,rectangular_region* recsb,int b_len){
    int i;
    for(i=0;i<a_len;i++){
        if(!rectangular_in_rectangulars(recsa+i,recsb,b_len))
            return false;
    }
    return false;
}
bool polygnal_in_rectangular(two_d_location* poly,int len,rectangular_region* rec){
    two_d_location *a;
    bool res;
    a = malloc(sizeof(two_d_location) * 4);
    if(a == NULL){
        wave_malloc_error();
        return -1;
    }
    rectangular_2_polygonal(rec,a);
    res = polygnal_in_polygnal(poly,len,a,4);
    free(a);
    return res;
}
bool polygnal_in_rectangulars(two_d_location *poly,int len,rectangular_region* recs,int rec_len){
    int i;
    for(i=0;i<rec_len;i++){
        if(polygnal_in_rectangular(poly,len,recs+i))
            return true;
    }
    return false;
}
bool circular_in_circular(circular_region *a,circular_region* b){
    double distance;
    distance = sqrt( (a->center.latitude - b->center.latitude) * (a->center.latitude - b->center.latitude) +
                        (a->center.longitude - b->center.longitude) *(a->center.longitude - b->center.longitude));
    if(a->radius + distance < b->radius)
        return true;
    return false;
}
bool two_d_location_in_circular(two_d_location* p,circular_region* circle){
    two_d_location *b,*a;
    u16 r;
    int i;
    double distance;
    b = &circle->center;
    r = circle->radius;
    
    a = p;
    distance = sqrt( (a->latitude - b->latitude) * (a->latitude - b->latitude) +
                        (a->longitude - b->longitude) *(a->longitude - b->longitude));
    if(distance > r)
            return false;
    return true;
}
bool polygnal_in_circular(two_d_location* poly,int len,circular_region* circle){
    int i; 
    for(i=0;i<len;i++){
        if(!two_d_location_in_circular(poly+i,circle))
            return false;
    }
    return true;
}
bool rectangular_in_circular(rectangular_region* rec,circular_region *circle){
    two_d_location *a;
    bool res;
    a = malloc(sizeof(two_d_location) * 4);
    if(a == NULL){
        wave_malloc_error();
        return -1;
    }
    rectangular_2_polygonal(rec,a);
    res = polygnal_in_circular(a,4,circle);
    free(a);
    return res;  
}
bool rectangulars_in_circular(rectangular_region* recs,int len,circular_region* circle){
    int i;
    for(i=0;i<len;i++){
        if(!rectangular_in_circular(recs+i,circle))
            return false;
    }
    return true;
}
/**
 * 所有的经纬度都是当成平面坐标来做的
 */
bool geographic_region_in_geographic_region(geographic_region *region_a,geographic_region *region_b){
    switch(region_a->region_type){
        case CIRCLE:
            switch(region_b->region_type){
                case CIRCLE:
                    return circular_in_circular(&region_a->u.circular_region,&region_b->u.circular_region);
                case RECTANGLE:
                    return circular_in_rectangulars(&region_a->u.circular_region,region_b->u.rectangular_region.buf,region_b->u.rectangular_region.len);
                case POLYGON:
                    return circular_in_polygonal(&region_a->u.circular_region,region_b->u.polygonal_region.buf,region_b->u.polygonal_region.len);
                default:
                    wave_error_printf("这个情况我处理不了 地理位置类型只能为三个中一个   %s %d",__FILE__,__LINE__);
                    return false;
            }
        case RECTANGLE:       
            switch(region_b->region_type){
                case CIRCLE:
                    return rectangulas_in_circular(region_a->u.rectangular_region.buf,region_a->u.rectangular_region.len,
                                                    &region_b->u.circular_region);
                case RECTANGLE:
                    return rectangulas_in_rectangulars(region_a->u.rectangular_region.buf,region_a->u.rectangular_region.len,
                                                        region_b->u.rectangular_region.buf,region_b->u.rectangular_region.len);
                case POLYGON:
                    return rectangulars_in_polygnal(region_a->u.rectangular_region.buf,region_a->u.rectangular_region.len,
                                                        region_b->u.polygonal_region.buf,region_b->u.polygonal_region.len);
                default:
                    wave_error_printf("这个情况我处理不了 地理位置类型只能为三个中一个   %s %d",__FILE__,__LINE__);
                    return false;
            }
        case POLYGON:
            switch(region_b->region_type){
                case CIRCLE:
                    return polygnal_in_circular(region_a->u.polygonal_region.buf,region_a->u.polygonal_region.len,
                                                    &region_b->u.circular_region);
                case RECTANGLE:
                    return polygnal_in_rectangulars(region_a->u.polygonal_region.buf,region_a->u.polygonal_region.len,
                                                        region_b->u.rectangular_region.buf,region_b->u.rectangular_region.len);
                case POLYGON:
                    return polygnal_in_polygnal(region_a->u.polygonal_region.buf,region_a->u.polygonal_region.len,
                                                        region_b->u.polygonal_region.buf,region_b->u.polygonal_region.len);
                default:
                    wave_error_printf("这个情况我处理不了 地理位置类型只能为三个中一个   %s %d",__FILE__,__LINE__);
                    return false;
            }
        default:
                wave_error_printf("这个情况我处理不了 地理位置类型只能为三个中一个   %s %d",__FILE__,__LINE__);
                return false;

    }
    return false;
}
bool three_d_location_in_region(three_d_location* loc,geographic_region* region){
    two_d_location p;
    two_d_location *poly;
    int i;

    p.latitude = loc->latitude;
    p.longitude = loc->longitude;
    switch(region->region_type){
        case CIRCLE:
                return two_d_location_in_circular(&p,&region->u.circular_region);
        case RECTANGLE:
                poly = (two_d_location*)malloc(sizeof(two_d_location) * 4);
                if(poly == NULL){
                    wave_malloc_error();
                    return false;
                }
                for(i=0;i<region->u.rectangular_region.len;i++){
                    rectangular_2_polygonal(region->u.rectangular_region.buf+i,poly);
                    if(two_d_location_in_polygonal(&p,poly,4))
                        return true;
                }
                free(poly);
                return false;
        case POLYGON:
                return two_d_location_in_polygonal(&p,region->u.polygonal_region.buf,region->u.polygonal_region.len);
        default:
                wave_error_printf("这个情况我处理不了 地理位置类型只能为三个中一个   %s %d",__FILE__,__LINE__);
                return false;
    }
    return false;
}
