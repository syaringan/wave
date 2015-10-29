/*************************************************************************
    > File Name: sec.c
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2015年10月15日 星期四 17时12分57秒
 ************************************************************************/

#include "./sec.h"
#include "../pssme/pssme.h"
#include "../data/data.h"
#include "../cme/cme.h"
#define INIT(m) memset(&m,0,sizeof(m))
//未测
result sec_signed_wsa(struct sec_db* sdb,string* data,serviceinfo_array* permissions,time32 life_time,string* signed_wsa){
    result ret = SUCCESS;
    struct certificate_chain chain;
    string permission_indices;
    cmh cmh;
    two_d_location td_location;
    tobesigned_wsa tbs_wsa;

    INIT(chain);
    INIT(permission_indices);
    INIT(td_location);
    INIT(tbs_wsa);

    ret = get_current_location(&td_location);
    if(ret != SUCCESS)
        goto fail;

    ret = pssme_cryptomaterial_handle(sdb, permissions, &td_location, &permission_indices, &cmh, &chain);
    if(ret != SUCCESS)
        goto fail;

    //填充tobesigned_wsa中的permission_indices
    tbs_wsa.permission_indices.len = permission_indices.len;
    tbs_wsa.permission_indices.buf = malloc(sizeof(u8)*permission_indices.len);
    if(tbs_wsa.permission_indices.buf == NULL){
        ret = FAILURE;
        goto fail;
    }
    memcpy(tbs_wsa.permission_indices.buf, permission_indices.buf, permission_indices.len*sizeof(u8));
    
    //设置use_location和use_generation_time flag
    tbs_wsa.tf = tbs_wsa.tf & USE_GENERATION_TIME & USE_LOCATION;

    //填充data
    tbs_wsa.data.len = data->len;
    tbs_wsa.data.buf = malloc(sizeof(u8)*data->len);
    if(tbs_wsa.data.buf == NULL){
        ret = FAILURE;
        goto fail;
    }
    memcpy(tbs_wsa.data.buf, data->buf, data->len*sizeof(u8));

    //对generation_time和generation_location编码填充，暂时没有

    tbs_wsa.expire_time = life_time;
    tbs_wsa.tf = tbs_wsa.tf & EXPIRES;

    //对tobesigned_wsa进行编码，然后签名，填充signed_wsa，暂时没有

fail:
    certificate_chain_free(&chain);
    string_free(&permission_indices);
    two_d_location_free(&td_location);
    tobesigned_wsa_free(&tbs_wsa);
    return ret;
}

result sec_check_certificate_chain_consistency(
                struct sec_db* sdb,
                struct certificate_chain* cert_chain,
                struct cme_permissions_array* permission_array,
                struct geographic_region_array* region){
    result ret = FOUND;
    int i = 0;

    for(i = cert_chain->len-1; i > 0; i--){
        switch(cert_chain->certs[i].unsigned_certificate.holder_type){
            case ROOT_CA:
                if(cert_chain->certs[i].unsigned_certificate.scope.u.root_ca_scope.permitted_holder_types & 
                        cert_chain->certs[i-1].unsigned_certificate.holder_type == 0){
                    ret = INCONSISITENT_CERTIFICATE_HOLDER_TYPE;
                    return ret;
                }
                break;
            case SDE_CA:
                if(cert_chain->certs[i].unsigned_certificate.scope.u.sde_ca_scope.permitted_holder_types & 
                        cert_chain->certs[i-1].unsigned_certificate.holder_type == 0){
                    ret = INCONSISITENT_CERTIFICATE_HOLDER_TYPE;
                    return ret;
                }
                break;
            case SDE_ENROLMENT:
                if(cert_chain->certs[i].unsigned_certificate.scope.u.sde_ca_scope.permitted_holder_types & 
                        cert_chain->certs[i-1].unsigned_certificate.holder_type == 0){
                    ret = INCONSISITENT_CERTIFICATE_HOLDER_TYPE;
                    return ret;
                }
                break;
            default:
                ret = INCONSISITENT_CERTIFICATE_HOLDER_TYPE;
                return ret;
        }
    }

    if(permission_array->cme_permissions[0].type == PSID || permission_array->cme_permissions[0].type == PSID_SSP){
        ret = sec_check_chain_psids_consistency(sdb, permission_array);
        if(ret != SUCCESS)
            return ret;
        for(i = 1; i < cert_chain->len-1; i++){
            if(cert_chain->certs[i].unsigned_certificate.holder_type != SDE_CA){
                ret = INCORRECT_CA_CERTIFICATE_TYPE;
                return ret;
            }
        }
    }
    if(permission_array->cme_permissions[0].type == PSID_PRIORITY || permission_array->cme_permissions[0].type == PSID_PRIORITY_SSP){
        ret = sec_check_chain_psid_priority_consistency(sdb, permission_array);
        if(ret != SUCCESS)
            return ret;
        for(i = 1; i < cert_chain->len-1; i++){
            if(cert_chain->certs[i].unsigned_certificate.holder_type != WSA_CA){
                ret = INCORRECT_CA_CERTIFICATE_TYPE;
                return ret;
            }
        }
    }
    for(i = 0; i < cert_chain->len; i++){
        if(cert_chain->certs[i].unsigned_certificate.expiration == 0 && cert_chain->certs[i].unsigned_certificate.crl_series == 0){
            ret = NON_REVOCABLE_NON_EXPIRING_CERTIFICATE;
            return ret;
        }
        if(i+1 < cert_chain->len){
            if(cert_chain->certs[i].unsigned_certificate.expiration > cert_chain->certs[i+1].unsigned_certificate.expiration){
                ret = INCONSISTENT_EXPIRY_TIMES;
                return ret;
            }
        }
        if(cert_chain->certs[i].unsigned_certificate.cf & 1){
            if(i+1 < cert_chain->len){
                if(cert_chain->certs[i].unsigned_certificate.flags_content.start_validity > 
                        cert_chain->certs[i+1].unsigned_certificate.expiration){
                    ret = INCONSISTENT_START_TIMES;
                    return ret;
                }
            }
            if(cert_chain->certs[i].unsigned_certificate.flags_content.start_validity > 
                    cert_chain->certs[i].unsigned_certificate.expiration){
                ret = START_VALIDITY_LATER_THAN_EXPIRATION;
                return ret;
            }
        }
    }
    ret = sec_check_chain_geographic_consistency(sdb, region);
    return ret;
}

result sec_check_chain_psids_consistency(struct sec_db* sdb,
                        struct cme_permissions_array* permission_array){
    result ret = SUCCESS;
    if(permission_array->len < 2){
        ret = INVALID_PERMISSION_TYPE;
        return ret;
    }
    if(permission_array->cme_permissions[0].type != PSID && permission_array->cme_permissions[0].type != PSID_SSP){
        ret = INVALID_PERMISSION_TYPE;
        return ret;
    }
    int i, j, k;
    for(i = 1; i < permission_array->len; i++){
        if(permission_array->cme_permissions[i].type != PSID){
            ret = INVALID_PERMISSION_TYPE;
            return ret; 
        }
        if(i == 1){
            if(permission_array->cme_permissions[i-1].type == PSID){
                for(j = 0; j < permission_array->cme_permissions[i-1].u.psid_array.len; j++){
                    for(k = 0; k < permission_array->cme_permissions[i].u.psid_array.len; k++){
                        if(permission_array->cme_permissions[i-1].u.psid_array.buf[j] == 
                                permission_array->cme_permissions[i].u.psid_array.buf[k])
                            break;
                    }
                    if(k == permission_array->cme_permissions[i].u.psid_array.len){
                        ret = INCONSISITENT_PERMISSIONS;
                        return ret;
                    }
                }
            }
            else{
                for(j = 0; j < permission_array->cme_permissions[i-1].u.psid_ssp_array.len; j++){
                    for(k = 0; k < permission_array->cme_permissions[i].u.psid_array.len; k++){
                        if(permission_array->cme_permissions[i-1].u.psid_ssp_array.buf[j].psid == 
                                permission_array->cme_permissions[i].u.psid_array.buf[k])
                            break;
                    }
                    if(k == permission_array->cme_permissions[i].u.psid_array.len){
                        ret = INCONSISITENT_PERMISSIONS;
                        return ret;
                    }
                }

            }
        }
        else{
            for(j = 0; j < permission_array->cme_permissions[i-1].u.psid_array.len; j++){
                for(k = 0; k < permission_array->cme_permissions[i].u.psid_array.len; k++){
                    if(permission_array->cme_permissions[i-1].u.psid_array.buf[j] == 
                            permission_array->cme_permissions[i].u.psid_array.buf[k])
                        break;
                }
                if(k == permission_array->cme_permissions[i].u.psid_array.len){
                    ret = INCONSISITENT_PERMISSIONS;
                    return ret;
                }
            }
        }
    }
    return ret;
}

result sec_check_chain_psid_priority_consistency(struct sec_db* sdb,
                        struct cme_permissions_array* permission_array){
    result ret = SUCCESS;
    if(permission_array->len < 2){
        ret = INVALID_PERMISSION_TYPE;
        return ret;
    }
    if(permission_array->cme_permissions[0].type != PSID_PRIORITY && permission_array->cme_permissions[0].type != PSID_PRIORITY_SSP){
        ret = INVALID_PERMISSION_TYPE;
        return ret;
    }
    int i, j, k;
    for(i = 1; i < permission_array->len-1; i++){
        if(permission_array->cme_permissions[i].type != PSID_PRIORITY && permission_array->cme_permissions[i].type != PSID_PRIORITY_SSP){
            ret = INVALID_PERMISSION_TYPE;
            return ret; 
        }

        int len1 = 0, len2 = 0;
        psid id1, id2;
        u8 priority1, priority2;
        enum permissions_type type1 = permission_array->cme_permissions[i].type;
        enum permissions_type type2 = permission_array->cme_permissions[i+1].type;
        if(type1 == PSID_PRIORITY)
            len1 = permission_array->cme_permissions[i].u.psid_priority_array.len;
        else
            len1 = permission_array->cme_permissions[i].u.psid_priority_ssp_array.len;
        if(type2 == PSID_PRIORITY)
            len2 = permission_array->cme_permissions[i+1].u.psid_priority_array.len;
        else
            len2 = permission_array->cme_permissions[i+1].u.psid_priority_ssp_array.len;
        for(j = 0; j < len1; j++){
            if(type1 = PSID_PRIORITY){
                id1 = permission_array->cme_permissions[i].u.psid_priority_array.buf[j].psid;
                priority1 = permission_array->cme_permissions[i].u.psid_priority_array.buf[j].max_priority;
            }
            else{
                id1 = permission_array->cme_permissions[i].u.psid_priority_ssp_array.buf[j].psid;
                priority1 = permission_array->cme_permissions[i].u.psid_priority_ssp_array.buf[j].max_priority; 
            }
            for(k = 0; k < len2; k++){
                if(type2 = PSID_PRIORITY){
                    id2 = permission_array->cme_permissions[i].u.psid_priority_array.buf[k].psid;
                    priority2 = permission_array->cme_permissions[i].u.psid_priority_array.buf[k].max_priority;
                }
                else{
                    id2 = permission_array->cme_permissions[i].u.psid_priority_ssp_array.buf[k].psid;
                    priority2 = permission_array->cme_permissions[i].u.psid_priority_ssp_array.buf[k].max_priority; 
                }
                if(id1 == id2)
                    break;
            }
            if(k == len2){
            if(type1 = PSID_PRIORITY){
                id1 = permission_array->cme_permissions[i].u.psid_priority_array.buf[j].psid;
                priority1 = permission_array->cme_permissions[i].u.psid_priority_array.buf[j].max_priority;
            }
            else{
                id1 = permission_array->cme_permissions[i].u.psid_priority_ssp_array.buf[j].psid;
                priority1 = permission_array->cme_permissions[i].u.psid_priority_ssp_array.buf[j].max_priority; 
            }
                ret = INCONSISITENT_PERMISSIONS;
                return ret;
            }
            if(priority1 > priority2){
                ret = INCONSISITENT_PERMISSIONS;
                return ret;
            }
        }
    }
    return ret;
}
