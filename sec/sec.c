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


static bool three_d_location_in_region(three_d_location* location,geographic_region* region){
   
   return true; 
};
static bool cme_permissions_contain_psid_with_ssp(struct cme_permissions* permission,psid psid,string* ssp){
    int i,j;
    psid_ssp *ps;
    psid_priority_ssp *ppssp;
    switch(permissions->type){
        case PSID:
            return false;
        case PSID_PRIORITY:
            return false;
        case PSID_SSP:
            for(i=0;i<permission.u.psid_ssp_array.len;i++){
                ps = permission.u.psid_ssp_array.buf+i;
                if(ps->psid == psid ){
                    if(ssp->len == ps->service_specific_permissions.len){
                        for(j=0;j<ssp->len;j++){
                            if( *(ssp->buf+j) != *(ps->service_specific_permissions.buf+j) )
                                break;
                        }
                        if(j == ssp->len){
                            return true;
                        }
                    }         
                }
            } 
            return false; 
        case PSID_PRIORITY_SSP:
            for(i=0;i<permission.u.psid_priority_ssp_array.len;i++){
                pps = permission.u.psid_priority_ssp_array.buf+i;
                if(pps->psid == psid ){
                    if(ssp->len == pps->service_specific_permissions.len){
                        for(j=0;j<ssp->len;j++){
                            if( *(ssp->buf+j) != *(pps->service_specific_permissions.buf+j) )
                                break;
                        }
                        if(j == ssp->len){
                            return true;
                        }
                    }         
                }
            } 
            return false; 
        case INHERITED_NOT_FOUND:
            wave_error_printf("这个应该怎么解释？？我没有解释，我直接返回错误");
            return false; 
    }
    return false;
}
result sec_signed_data(struct sec_db* sdb,cmh cmh,content_type type,string* data,string* exter_data,psid psid,
                    string* ssp,bool set_generation_time, time64_with_standard_deviation* generation_time,
                    bool set_generation_location,three_d_location* location,bool set_expiry_time,time64 expiry_time,
                    signer_identifier_type signer_type,s32 cert_chain_len,u32 cert_chain_max_len,enum sign_with_fast_verification fs_type,
                    bool comperssed,
                    
                    string* signed_data,u32* len_of_cert_chain){
    if(signed_data != NULL && signed_data.buf != NULL ){
        wave_error_printf("string的buf没有清空，肯能存在野指针");
        return FAILURE;
    }
    
    result res;
    certificate cert;
    certificate_chain cert_chain,construct_cert_chain;
    geographic_region_array regions;
    cme_permissions_array permissions;
    tobesigned_data tbs_encode,tbs_sign;
    signed_data s_data;
    time32 start_time,expired_time;

    res = SUCCESS;
    INIT(cert);
    INIT(cert_chain);
    INIT(construct_cert_chain);
    INIT(region);
    INIT(permissions);
    INIT(tbs_encode);
    INIT(tbs_sign);
    INIT(s_data);
   
    if( res = find_cert_by_cmh(sdb,&cmh,&cert) ){
        goto fail;
    }

    cert_chain.certs = &cert; 
    cert_chain.len = 1;
    res = cme_construct_certificate_chain(sdb,ID_CERTIFICATE,NULL,&cert_chain,true,cert_chain_max_len,
                    &construct_cert_chain,&permissions,&regions,NULL,NULL,NULL);
    if(res != FOUND){
        goto fail;
    }
    if(certificate_get_start_time(&cert,&start_time) || 
            certificate_get_expired_time(&cert,&expired_time)){
        wave_error_printf("获取证书相关信息不对，这个证书没有这个信息");
        res = FAILURE;
        goto fail;
    }
    if(generation_time.time < start_time){
        wave_error_printf("生产时期早于了证书的开始有效时间");
        res = CERTIFICATE_NOT_YET_VALID;
        goto fail;
    }
    if(generation_time.time > expired_time){
         wave_error_printf("生产日期晚育了证书的结束有效时间");
         res = CERTIFICATE_EXPIRED;
         goto fail;
    }
    if(set_expiry_time){
        if(exprity_time < start_time){
            wave_error_printf("过期时间早育了证书的开始有效时间");
            res = EXPIRY_TIME_BEFORE_CERTIFICATE_VALIDITY_PERIOD;
            goto fail;
        }
        if(exprity_time > expired_time){
            wave_error_printf("过期时间晚育了证书的结束的有效时间");
            res = EXPIRY_TIME_AFTER_CERTIFICATE_VALIDITY_PERIOD;
            goto fail;
        }
    }
    if( three_d_location_in_region(location,regions.regions) == false){
        wave_error_printf("生产地点不在证书范围内");
        res = OUTSIDE_CERTIFICATE_VALIDITY_REGION;
        goto fail;
    }
    if( cme_permissions_contain_psid_with_ssp(permissions.cme_permissions,psid,ssp) ==false){
        wave_error_printf("证书权限和用户要求的不一致");
        res = INCONSISTENT_PERMISSIONS_IN_CERTIFICATE;
        goto fail;
    }

    if(signer_type == CERTIFICATE_CHAIN && 
            (cert_chain_len > construct_cert_chain.len || -cert_chain_len > construct_cert_chain.len)){
        if(len_of_cert_chain != NULL)
            *len_of_cert_chain = construct_cert_chain.len;
        wave_error_printf("证书连请求长度请求不正确");
        res = INCORRECT_REQUSET_CERTIFICATE_CHAIN_LENGTH;
        goto fail;
    } 

    switch(type){
        case SIGNED:
            tbs_encode.u.type_signed.psid = psid;
            break;
        case SIGNED_PARTIAL_PAYLOAD:
            tbs_encode.u.type_signed_partical.psid = psid;
            break;
        case SIGNED_EXTERNAL_PAYLOAD:
            tbs_encode.u.psid = psid;
            tbs_encode.u.
            break;
        default:
            wave_error_printf("这个指的话，是没有psid的。。怎么版，我只有返回错误");
            res = FAILURE;
            goto fail;
    }
    if(set_generation_time){
        tbs_encode.tf |= USE_GENERATION_TIME;
        tbs_encode.flags_content.generation_time.time = generation_time.time;
        tbs_encode.flags_content.generation_time.long_std_dev = generation_time.long_std_dev;
    }
    if(set_generation_location){
        tbs_encode.tf |= USE_LOCATION;
        tbs_encode.flags_content.generation_location.latitude = location->latitude;
        tbs_encode.flags_content.generation_location.longitude = location->longitude;
        tbs_encode.flags_content.generation_location.elevation[0] = location->elevation[0];
        tbs_encode.flags_content.generation_location.elevation[1] = location->elevation[1];
    }
    if(set_expiry_time){
        tbs_encode.tf |= EXPIRES;
        tbs_encode.flags_content.exipir_time = expiry_time; 
    }
     
fail:
    certificate_free(&cert);
    //certificate_chain_free(&cert_chain);
    cert_chain.certs = NULL;
    cert_chain.len = 0;
    certificate_chain_free(&construct_cert_chain);
    geographic_region_free(&region);
    cme_permissions_free(&permissions);
    tobesigned_data_free(&tbs_encode);
    tobesigned_data_free(&tbs_sign);
    signed_data_free(&s_data);
    return res;
}
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

    ret = pssme_cryptomaterial_handle(sdb, permissions, &two_dl, &permission_indices, &cmh, &chain);
    if(ret != SUCCESS)
        goto fail;

    //填充tobesigned_wsa中的permission_indices
    tbs_wsa.permission_indices.len = permission_indices.len;
    tbs_wsa.permission_indices.buf = malloc(sizeof(u8)*permission_indices->len);
    if(tbs_wsa.permission_indices.buf == NULL){
        ret = FAILURE;
        goto fail;
    }
    memcpy(tbs_wsa.permission_indices.buf, permission_indices.buf, permission_indices.len);
    
    //设置use_location和use_generation_time flag
    tbs_wsa.tf = tbs_wsa.tf & USE_GENERATION_TIME & USE_LOCATION;

    //填充data
    tbs_wsa.data.len = data->len;
    tbs_wsa.data.buf = malloc(sizeof(u8)*data->len);
    if(tbs_wsa.data.buf == NULL){
        ret = FAILURE;
        goto fail;
    }
    memcpy(tbs_wsa.data.buf, data->buf, data->len);

    //对generation_time和generation_location编码填充，暂时没有

    tbs_wsa.expiry_time = life_time;
    tbs_wsa.tf = tbs_wsa.tf & EXPIRES;

    //对tobesigned_wsa进行编码，然后签名，填充signed_wsa，暂时没有
    }

fail:
    certificate_chain_free(&chain);
    string_free(&permission_indices);
    two_d_location_free(&td_location);
    tobesigned_wsa_free(&tbs_wsa);
    return ret;
}
