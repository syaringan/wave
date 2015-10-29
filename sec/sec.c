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
    psid_priority_ssp *pps;
    switch(permission->type){
        case PSID:
            return false;
        case PSID_PRIORITY:
            return false;
        case PSID_SSP:
            for(i=0;i<permission->u.psid_ssp_array.len;i++){
                ps = permission->u.psid_ssp_array.buf+i;
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
            for(i=0;i<permission->u.psid_priority_ssp_array.len;i++){
                pps = permission->u.psid_priority_ssp_array.buf+i;
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
//cert_chani_len == 257的时候代表MAX
result sec_signed_data(struct sec_db* sdb,cmh cmh,content_type type,string* data,string* exter_data,psid psid,
                    string* ssp,bool set_generation_time, time64_with_standard_deviation* generation_time,
                    bool set_generation_location,three_d_location* location,bool set_expiry_time,time64 expiry_time,
                    enum signed_data_signer_type signer_type,s32 cert_chain_len,u32 cert_chain_max_len,enum sign_with_fast_verification fs_type,
                    bool comperssed,
                    
                    string* signed_data,u32* len_of_cert_chain){
    if(signed_data != NULL && signed_data->buf != NULL ){
        wave_error_printf("string的buf没有清空，肯能存在野指针");
        return FAILURE;
    }
    
    result res;
    certificate cert;
    struct certificate_chain cert_chain,construct_cert_chain;
    struct geographic_region_array regions;
    struct cme_permissions_array permissions;
    tobesigned_data *tbs_encode,*tbs_sign;//后面这个都没有用，但是协议出现了，，我先保存
    sec_data sec_data;
    struct signed_data  *s_data;
    time32 start_time,expired_time;
    string encoded_tbs,hashed_tbs,signed_tbs,privatekey,hash8;
    elliptic_curve_point point;
    pk_algorithm algorithm = 100;//这里让他等于一个不可能的指
    int i;

    res = SUCCESS;
    INIT(cert);
    INIT(cert_chain);
    INIT(construct_cert_chain);
    INIT(regions);
    INIT(permissions);
    //INIT(tbs_encode);
   // INIT(tbs_sign);
   // INIT(s_data);
    INIT(sec_data);
    INIT(encoded_tbs);
    INIT(hashed_tbs);
    INIT(signed_tbs);
    INIT(privatekey);
    INIT(hash8);
    INIT(point);
    
    s_data = &sec_data.u.signed_data;
    tbs_encode = &s_data->unsigned_data;
    if( res = find_cert_prikey_by_cmh(sdb,cmh,&cert,&privatekey) ){
        goto fail;
    }
    
    cert_chain.certs = &cert;
    if(  cme_construct_certificate_chain(sdb,ID_CERTIFICATE,NULL,&cert_chain,true,cert_chain_max_len,
                &construct_cert_chain,&permissions,&regions,NULL,NULL,NULL)  != FOUND){
        res = NOT_FOUND;
        goto fail;
    }
    if(certificate_get_start_time(&cert,&start_time) || 
            certificate_get_expired_time(&cert,&expired_time)){
        wave_error_printf("获取证书相关信息不对，这个证书没有这个信息");
        res = FAILURE;
        goto fail;
    }
    if(generation_time->time < start_time){
        wave_error_printf("生产时期早于了证书的开始有效时间");
        res = CERTIFICATE_NOT_YET_VALID;
        goto fail;
    }
    if(generation_time->time > expired_time){
         wave_error_printf("生产日期晚育了证书的结束有效时间");
         res = CERTIFICATE_EXPIRED;
         goto fail;
    }
    if(set_expiry_time){
        if(expiry_time < start_time){
            wave_error_printf("过期时间早育了证书的开始有效时间");
            res = EXPIRY_TIME_BEFORE_CERTIFICATE_VALIDITY_PERIOD;
            goto fail;
        }
        if(expiry_time > expired_time){
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
            tbs_encode->u.type_signed.psid = psid;
            
            tbs_encode->u.type_signed_partical.data.len = data->len;
            tbs_encode->u.type_signed_partical.data.buf = 
                    (u8*)malloc(data->len);
            if(tbs_encode->u.type_signed_partical.data.buf == NULL){
                wave_malloc_error();
                goto fail;
            }
            memcpy(tbs_encode->u.type_signed_partical.data.buf,data->buf,data->len);
            break;
        case SIGNED_PARTIAL_PAYLOAD:
            tbs_encode->u.type_signed_partical.psid = psid;

            tbs_encode->u.type_signed_partical.data.len = data->len;
            tbs_encode->u.type_signed_partical.data.buf = 
                    (u8*)malloc(data->len);
            if(tbs_encode->u.type_signed_partical.data.buf == NULL){
                wave_malloc_error();
                goto fail;
            }
            memcpy(tbs_encode->u.type_signed_partical.data.buf,data->buf,data->len);

            if(exter_data != NULL){
                tbs_encode->u.type_signed_partical.ext_data.len = exter_data->len;
                tbs_encode->u.type_signed_partical.ext_data.buf = 
                    (u8*)malloc(exter_data->len);
                if(tbs_encode->u.type_signed_partical.ext_data.buf == NULL){
                    wave_malloc_error();
                    goto fail;
                }
                memcpy(tbs_encode->u.type_signed_partical.ext_data.buf,exter_data->buf,exter_data->len);
            }
            break;
        case SIGNED_EXTERNAL_PAYLOAD:
            tbs_encode->u.type_signed_external.psid = psid;
           
            if(exter_data != NULL){
                tbs_encode->u.type_signed_external.ext_data.len = exter_data->len;
                tbs_encode->u.type_signed_external.ext_data.buf = 
                    (u8*)malloc(exter_data->len);
                if(tbs_encode->u.type_signed_external.ext_data.buf == NULL){
                    wave_malloc_error();
                    goto fail;
                }
                memcpy(tbs_encode->u.type_signed_external.ext_data.buf,exter_data->buf,exter_data->len);
            }
            else{
                wave_error_printf("模式为external_payload,但是你的exter_data为null");
                goto fail;
            }
            break;
        default:
            wave_error_printf("这个指的话，是没有psid的。。怎么版，我只有返回错误,要不我这里暂时不支持这种");
            res = FAILURE;
            goto fail;
    }
    if(set_generation_time){
        tbs_encode->tf |= USE_GENERATION_TIME;
        tbs_encode->flags_content.generation_time.time = generation_time->time;
        tbs_encode->flags_content.generation_time.long_std_dev = generation_time->long_std_dev;
    }
    if(set_generation_location){
        tbs_encode->tf |= USE_LOCATION;
        tbs_encode->flags_content.generation_location.latitude = location->latitude;
        tbs_encode->flags_content.generation_location.longitude = location->longitude;
        tbs_encode->flags_content.generation_location.elevation[0] = location->elevation[0];
        tbs_encode->flags_content.generation_location.elevation[1] = location->elevation[1];
    }
    if(set_expiry_time){
        tbs_encode->tf |= EXPIRES;
        tbs_encode->flags_content.exipir_time = expiry_time; 
    }

    if( tobesigned_data_2_string(&tbs_encode,&encoded_tbs) ){
        wave_error_printf("编码失败");
        goto fail;
    }
    
    //我要hash和签名了
    switch(cert.version_and_type){
        case 2:
            if(cert.unsigned_certificate.holder_type  == ROOT_CA){
                switch(cert.unsigned_certificate.version_and_type.verification_key.algorithm){
                    case ECDSA_NISTP224_WITH_SHA224:
                       algorithm = ECDSA_NISTP224_WITH_SHA224;
                       if( crypto_HASH224(&encoded_tbs,&hashed_tbs) ){
                            goto fail;
                       }  
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       algorithm = ECDSA_NISTP256_WITH_SHA256;
                       if( crypto_HASH256(&encoded_tbs,&hashed_tbs))
                           goto fail;
                       break;
                    case ECIES_NISTP256:
                       wave_error_printf("这个是加密算法，怎么出现在了这个签名中");
                       goto fail;
                       break;
                }
                if(crypto_ECDSA_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           goto fail;
            }
            else{
                switch(cert.unsigned_certificate.u.no_root_ca.signature_alg){
                    case ECDSA_NISTP224_WITH_SHA224:
                       algorithm = ECDSA_NISTP224_WITH_SHA224;
                       if( crypto_HASH224(&encoded_tbs,&hashed_tbs) ){
                            goto fail;
                       }  
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       algorithm = ECDSA_NISTP256_WITH_SHA256;
                       if( crypto_HASH256(&encoded_tbs,&hashed_tbs))
                           goto fail;
                       break;
                    case ECIES_NISTP256:
                       wave_error_printf("这个是加密算法，怎么出现在了这个签名中");
                       goto fail;
                       break;
                }
                if(crypto_ECDSA_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           goto fail;
            }
            break;
        case 3:
             switch(cert.unsigned_certificate.u.no_root_ca.signature_alg){
                    case ECDSA_NISTP224_WITH_SHA224:
                       algorithm = ECDSA_NISTP224_WITH_SHA224;
                       if( crypto_HASH224(&encoded_tbs,&hashed_tbs) ){
                            goto fail;
                       }  
                       if(crypto_ECDSA_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                            goto fail;
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       algorithm = ECDSA_NISTP256_WITH_SHA256;
                       if( crypto_HASH256(&encoded_tbs,&hashed_tbs))
                           goto fail;
                       if(crypto_ECDSA_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                            goto fail;
                       break;
                    case ECIES_NISTP256:
                       wave_error_printf("这个是加密算法，怎么出现在了这个签名中");
                       goto fail;
                       break;
            } 
            break;
        default:
            wave_error_printf("出现了不可能出现的指 %s %d ",__FILE__,__LINE__);
            goto fail;
    }

    if(signer_type == SIGNED_DATA_CERTIFICATE_DIGEST){
        s_data->signer.type = algorithm;
        if( certificate_2_hash8(&cert,&hash8))
            goto fail;
        memcpy(s_data->signer.u.digest.hashedid8, hash8.buf,8);
        //这里是1嘛？？协议没说，我按照自己的想法加的
        if(len_of_cert_chain != NULL)
                *len_of_cert_chain = 1;
    }
    else if(signer_type == SIGNED_DATA_CERTIFICATE){
        s_data->signer.type = CERTIFICATE;
        certificate_cpy(&s_data->signer.u.certificate,&cert);
        //这里是1嘛？？协议没说，我按照自己的想法家的
        if(len_of_cert_chain != NULL)
                *len_of_cert_chain = 1;

    }
    else if(signer_type == SIGNED_DATA_CERTIFICATE_CHAIN){
        s_data->signer.type = CERTIFICATE_CHAIN;
        if(cert_chain_len == 257){//为max
            s_data->signer.u.certificates.buf = (certificate*)malloc(sizeof(certificate) *
                    construct_cert_chain.len);
            if(s_data->signer.u.certificates.buf == NULL){
                wave_malloc_error();
                goto fail;
            }
            s_data->signer.u.certificates.len = construct_cert_chain.len;
            for(i=0;i<construct_cert_chain.len;i++){
                certificate_cpy(s_data->signer.u.certificates.buf+i,construct_cert_chain.certs+i);
            }
        }
        else if(cert_chain_len > 0){
            if(cert_chain_len >  construct_cert_chain.len){
                wave_printf(MSG_WARNING,"要求的证书连长度:%d  大于了生成的证书连长度:%d\n",cert_chain_len,construct_cert_chain.len);
                s_data->signer.u.certificates.len = construct_cert_chain.len;
            }
            else
                s_data->signer.u.certificates.len = cert_chain_len;
            s_data->signer.u.certificates.buf = (certificate*)malloc(sizeof(certificate) *
                   s_data->signer.u.certificates.len);
            if(s_data->signer.u.certificates.buf == NULL){
                wave_malloc_error();
                goto fail;
            } 
            for(i=0;i<s_data->signer.u.certificates.len;i++){
                certificate_cpy(s_data->signer.u.certificates.buf+i,construct_cert_chain.certs+i);
            }            
        }
        else if(cert_chain_len <0){
            if(construct_cert_chain.len - 1 < -cert_chain_len){
                wave_error_printf("要求删掉的链表长度长于生成的链表长度 %s %d\n",__FILE__,__LINE__);
                goto fail;
            }
            s_data->signer.u.certificates.len = construct_cert_chain.len + cert_chain_len;
            s_data->signer.u.certificates.buf = (certificate*)malloc(sizeof(certificate) *
                   s_data->signer.u.certificates.len);
            if(s_data->signer.u.certificates.buf == NULL){
                wave_malloc_error();
                goto fail;
            }
            certificate_cpy(s_data->signer.u.certificates.buf,construct_cert_chain.certs);
            //这里我不知道我的理解对不，是负数，就删除前面几个，但是第一个不删除;
            for(i=0;i<-cert_chain_len -1;i++){
                certificate_cpy(s_data->signer.u.certificates.buf+i,construct_cert_chain.certs+i-cert_chain_len+1);
            }
           
        }
        else{
            wave_error_printf("证书连要求长度为0，这个我不知道怎么半，我直接返回错误");
            goto fail;
        }
        if(len_of_cert_chain != NULL)
                *len_of_cert_chain = s_data->signer.u.certificates.len;
    }
    else{
        wave_error_printf("这个signer_type出现了不正确的指");
        goto fail;
    }
     
    if(algorithm != ECDSA_NISTP224_WITH_SHA224 || algorithm != ECDSA_NISTP256_WITH_SHA256){
        wave_error_printf("这里的协议类型都不等于我们要求的这里有问题,我们这里暂时不支持其他的加密算法");
        goto fail;
    }
    s_data->signature.u.ecdsa_signature.s.len = signed_tbs.len;
    s_data->signature.u.ecdsa_signature.s.buf = (u8*)malloc(signed_tbs.len);
    if(s_data->signature.u.ecdsa_signature.s.buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    memcpy(s_data->signature.u.ecdsa_signature.s.buf,signed_tbs.buf,signed_tbs.len);

//这个地方到底是什么情况type是什么指，还有什么时候压缩，压缩了是取1还是0啊。。这个地方我真的不确定哦
//这里我们王signature里面添加的椭圆点，的依据是从这个证书里面的椭圆点取出来嘛。。。那么证书里面的椭圆点如果有压缩了，
//我们signature要求不压缩，那我是不是要解压，，但是我暂时不懂怎么弄，所以我不能处理的情况我会返回错误。
//还有这里compressed和fs_type到底怎么联合起来确定signature的type;
    certificate_get_elliptic_curve_point(&cert,&point);
    switch(fs_type){
        case NO: 
            s_data->signature.u.ecdsa_signature.r.type = X_COORDINATE_ONLY;
            if(algorithm == ECDSA_NISTP224_WITH_SHA224){
                s_data->signature.u.ecdsa_signature.r.x.buf = (u8*)malloc(28);
                if(s_data->signature.u.ecdsa_signature.r.x.buf == NULL){
                    wave_malloc_error();
                    goto fail;
                }
                //这里是这样嘛，我只是把x复制过去了，y都不知道需要不，这里应该是把证书里面的公钥拿出来，这里y都不要
                //对面能解嘛。
                s_data->signature.u.ecdsa_signature.r.x.len = 28;
                memcpy(s_data->signature.u.ecdsa_signature.r.x.buf,point.x.buf,28);
            }
            else if(algorithm == ECDSA_NISTP256_WITH_SHA256){
                s_data->signature.u.ecdsa_signature.r.x.buf = (u8*)malloc(32);
                if(s_data->signature.u.ecdsa_signature.r.x.buf == NULL){
                    wave_malloc_error();
                    goto fail;
                }
                s_data->signature.u.ecdsa_signature.r.x.len = 32;
                memcpy(s_data->signature.u.ecdsa_signature.r.x.buf,point.x.buf,32);
            }
            break;
        case YES_UNCOMPRESSED:
            s_data->signature.u.ecdsa_signature.r.type = UNCOMPRESSED;
            if( point.type != UNCOMPRESSED){
                wave_error_printf("这里出现了不对等的情况，我处理不来了，，我当成错误出来了 %s %d",__FILE__,__LINE__);
                goto fail;    
            }
            s_data->signature.u.ecdsa_signature.r.x.len = point.x.len;
            s_data->signature.u.ecdsa_signature.r.u.y.len = point.u.y.len;
            s_data->signature.u.ecdsa_signature.r.x.buf = (u8*)malloc(point.x.len);
            s_data->signature.u.ecdsa_signature.r.u.y.buf = (u8*)malloc(point.u.y.len);
            if(s_data->signature.u.ecdsa_signature.r.x.buf == NULL ||
                    s_data->signature.u.ecdsa_signature.r.u.y.buf == NULL){
                wave_malloc_error();
                goto fail;
            }
            memcpy(s_data->signature.u.ecdsa_signature.r.x.buf,point.x.buf,point.x.len);
            memcpy(s_data->signature.u.ecdsa_signature.r.u.y.buf,point.u.y.buf,point.u.y.len);
            break;
        case YES_COMPRESSED:
            if(point.type != COMPRESSED_LSB_Y_0 && point.type !=COMPRESSED_LSB_Y_1){
                wave_error_printf("这里出现了不对等的情况，我处理不来了，，我当成错误出来了 %s %d",__FILE__,__LINE__);
                goto fail;
            } 
            s_data->signature.u.ecdsa_signature.r.type = point.type;
            
            s_data->signature.u.ecdsa_signature.r.x.len = point.x.len;
            s_data->signature.u.ecdsa_signature.r.x.buf = (u8*)malloc(point.x.len);
            if(s_data->signature.u.ecdsa_signature.r.x.buf == NULL){
                wave_malloc_error();
                goto fail;
            }
            memcpy(s_data->signature.u.ecdsa_signature.r.x.buf,point.x.buf,point.x.len);
            break;
         default:
            wave_error_printf("出现了不可能出现的指");
            goto fail;
    }
    if( sec_data_2_string(&sec_data,signed_data)){
        goto fail;
    }
    res = SUCCESS;
    goto fail;
    
fail:
    certificate_free(&cert);
    //certificate_chain_free(&cert_chain);
    cert_chain.certs = NULL;
    cert_chain.len = 0;
    certificate_chain_free(&construct_cert_chain);
    geographic_region_array_free(&regions);
    cme_permissions_array_free(&permissions);
    //tobesigned_data_free(&tbs_encode);
    //tobesigned_data_free(&tbs_sign);
    //signed_data_free(&s_data);
    sec_data_free(&sec_data);
    string_free(&encoded_tbs);
    string_free(&hashed_tbs);
    string_free(&signed_tbs);
    string_free(&privatekey);
    string_free(&hash8);
    elliptic_curve_point_free(&point);
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
