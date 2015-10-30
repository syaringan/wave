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
#include <time.h>
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
    pk_algorithm algorithm = PK_ALGOTITHM_NOT_SET;//这里让他等于一个不可能的指
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


result sec_encrypted_data(struct sec_db* sdb,content_type type,string* data,struct certificate_chain* certs,
                bool compressed,time64 time,
                
                string* encrypted_data,struct certificate_chain* failed_certs){
    if(encrypted_data == NULL || encrypted_data.buf != NULL ||failed_certs == NULL
            failed_certs.certs != NULL){
        wave_error_printf("参数有问题 %s %d",__FILE__,__LINE__);
    }
    
    result res = SUCCESS;
    certificate_chain enc_certs;
    certificate *temp_cert;
    symm_algorithm symm_alg = SYMM_ALGORITHM_NOT_SET,current_symm_alg;//表示没有设定
    int i;
    string symm_key;
    string cert_string;
    string ok;
    sec_data sdata;
    recipient_info *rec_info; 
    time32 next_crl_time;
    time_t now;

    INIT(enc_certs);
    INIT(symm_key);
    INIT(cert_string);
    INIT(ok);
    INIT(sdata);
    
    failed_certs->len = 0;
    for(i=0;i<certs->len;i++){
        string_free(cert_string);
        temp_cert = certs->certs+i;
        if( certificate_2_string(temp_cert,&cert_string))
            goto end;
        res = cme_certificate_info_request(sdb,ID_CERTIFICATE,&cert_string, 
                            NULL,NULL,NULL,&next_crl_time,NULL,NULL);
        if(res != FOUND){
            res = FAIL_ON_SOME_CERTIFICATES;
            if(certificate_chain_add_cert(failed_certs,temp_cert))
                goto end;
        }
        else{
            time(&now);
            if(next_crl_time < now - OVERDUE_CRL_TOLERANCE){
                wave_printf(MSG_WARNING,"crl没有获得，crl_next_time:%d  now:%d  over:OVERDUE_CRL_TOLERANCE\n",
                        next_crl_time,now);
                res = FAIL_ON_SOME_CERTIFICATES;
                if(certificate_chain_add_cert(failed_certs,temp_cert))
                    goto end;
            }
            else{
                if(temp_cert->version_and_type != 2 ||
                        temp_cert->unsigned_certificate.version_and_type.verification_key.algorithm !=
                            ECIES_NISTP256){
                    wave_error_printf("这个证书version_and_type != 2 或者algroithm != ECIES_NISTP256  %s %d"
                            ,__FILE__,__LINE__);
                    res = FAIL_ON_SOME_CERTIFICATES;
                    if(certificate_chain_add_cert(failed_certs,temp_cert))
                        goto end;
                }
                else{
                    current_symm_alg = temp_cert->unsigned_certificate.version_and_type.verification_key.
                                            u.ecies_nistp256.supported_symm_alg;
                    if(current_symm_alg != AES_128_CCM){
                        wave_error_printf("我们目前支持的加密算法只有AES_128_CCM %s %d",__FILE__,__LINE__);
                        res = FAIL_ON_SOME_CERTIFICATES;
                        if(certificate_chain_add_cert(failed_certs,temp_cert))
                            goto end;
                    }
                    else{
                        //这个地方我不知道我理解对没有，，请后来的人在核实一下，我是按照我的逻辑和想法猜测的
                        if(symm_algorithm != SYMM_ALGORITHM_NOT_SET && symm_algorithm != current_symm_alg){
                            res = FAIL_ON_SOME_CERTIFICATES;
                            if(certificate_chain_add_cert(failed_certs,temp_cert))
                                goto end;
                        }
                        else{
                            symm_algorithm = current_symm_alg;
                            if(certificate_chain_add_cert(&enc_certs,temp_cert))
                                goto end;
                        }
                    }
                }
            }
        }
    }
    if(enc_certs.len == 0){
        res = FAIL_ON_ALL_CERTIFICATES;
        goto end;
    }
    sdata.u.encrypted_data.recipients.buf = (recipient_info*)malloc(sizeof(recipient_info) * enc_certs.len);
    if(sdata.u.encrypted_data.recipients.buf == NULL){
        wave_malloc_error();
        goto end;
    }
    sdata.u.encrypted_data.recipients.len = enc_certs.len;

    /****
     *这里随即产生一个对等加密的key 然后写进ok里面
     */

    for(i=0;i<enc_certs.len;i++){
        rec_info = sdata.u.encrypted_data.recipients.buf+i;

    }
    //这里等待后面书写
end:
    string_free(&symm_key);
    certificate_chain_free(&enc_certs);
    string_free(&cert_string);
    string_free(&ok);
    sec_data_free(&sdata);
    return res;
}



result sec_secure_data_content_extration(struct sec_db* sdb,string* recieve_data,cmh cmh ,
        
                            content_type *content_type,content_type *inner_type,string* data,
                            string* signed_data,psid *psid,
                            string* ssp, bool* set_generation_time,
                            time64_with_standard_deviation *generation_time,
                            bool* set_expiry_time,time64* expiry_time,bool* set_generation_location,
                            three_d_location* location,certificate* send_cert){
    result res;
    sec_data sdata;
    encrypted_data *enc_data;
    struct signed_data *s_data;
    struct signer_identifier *signer;
    string temp;
    content_type type;
    bool verified;
    psid m_psid;
    struct cme_permissions permissions;
    int i;

    INIT(sdata);
    INIT(temp);
    INIT(permissions);

    if(  string_2_sec_data(recieve_data,&sdata)){
        wave_error_printf("不能将受到的数据变为sdata %s %d",__FILE__,__LINE__);
        res = INVAID_INPUT;
        goto end;
    }
    if(content_type != NULL)
        *content_type = sdata.type;
    type = sdata.type;

    if(sdata.protocol_version != CURRETN_VERSION){
        wave_error_printf("这个数据不是本版本的 %s %d",__FILE__,__LINE__);
        res = FAILURE;
        goto end;
    }
    switch(type){
        case ENCRYPTED:
            enc_data = &sdata.u.encrypted_data;
            if( encrypted_data_2_string(enc_data,&temp)){
                wave_error_printf("转化失败 %s %d",__FILE__,__LINE__);
                res = FAILURE;
                goto fail;
            }
            //这里我觉得逻辑有错，我并没有按照协议的走，，如果出现bug请核对哈
            res = sec_decrypt_data(sdb,&temp,cmh, inner_type,data);
            if(res != SUCCESS){
                goto end;
            }
            break;
        case UNSECURED:
            if(data != NULL){
                if(data->buf != NULL){
                    wave_error_printf("存在野指针 %s %d",__FILE__,__LINE__);
                    res = FAILURE;
                    goto end;
                }
                data->buf = (u8*)malloc(sdata.u.data.len);
                if(data->buf == NULL){
                    res = FAILURE;
                    wave_malloc_error();
                    goto end;
                }
                data->len = sdata.u.data.len;
                memcpy(data->buf,sdata.u.data.buf,data->len);
            }
            goto end;
        case SIGNED: 
        case SIGNED_PARTIAL_PAYLOAD:
        case SIGNED_EXTERNAL_PAYLOAD:
            s_data = &sdata.u.signed_data;
            switch(type){
                case SIGNED:
                    m_psid = s_data->unsigned_data.u.type_signed.psid; 
                    break;
                case SIGNED_PARTIAL_PAYLOAD:
                    m_psid = s_data->unsigned_data.u.type_signed_partical.psid;
                    break;
                case SIGNED_EXTERNAL_PAYLOAD:
                    m_psid = s_data->unsigned_data.u.type_signed_external.psid;
                    break;
            }
            if(psid != NULL)
                *psid = m_psid;
            if(s_data->unsigned_data.tf & USE_GENERATION_TIME){
                if(set_generation_time != NULL){
                    *set_generation_time = true;
                    if(generation_time != NULL){
                        memcpy(generation_time,&s_data->unsigned_data.flags_content.generation_time,
                                sizeof(time64_with_standard_deviation));
                    }
                }
            }
            else{
                if(set_generation_time != NULL)
                    *set_generation_time = false;
            }

            if(s_data->unsigned_data.tf & EXPIRES){
                if(set_expiry_time != NULL){
                    *set_expiry_time = true;
                    if(expire_time != NULL)
                        *expire_time = s_data->unsigned_data.flags_content.exipir_time;
                }
            }
            else{
                if(set_expiry_time != NULL)
                    *set_expiry_time = false;
            }

            if(s_data->unsigned_data.tf & USE_LOCATION){
                if(set_generation_location != NULL)
                    *set_generation_location = true;
                if(location != NULL){
                    memcpy(location,&s_data->unsigned_data.flags_content.generation_location,sizeof(three_d_location));
                }
            }
            else{
                if(set_generation_location != NULL)
                    *set_generation_location = false;
            }

            signer = &s_data.signer;
            string_free(&temp);
            if(signer->type == CERTIFICATE || signer->type == CERTIFICATE_CHAIN ){
                if(signer->type == CERTIFICATE ){
                    certificate_2_string(&signer->u.certificate,&temp);
                }
                else if(signer->type == CERTIFICATE_CHAIN){
                    certificate_2_string(signer->u.certificates.buf+signer->u.certificates.len-1,&temp);
                }
                res = cme_certificate_info_request(sdb,ID_CERTIFICATE,&temp, NULL,&permissions,NULL,NULL,
                            NULL,NULL,&verified);
                if(res == CERTIFICATE_NOT_FOUND){
                    if(signer->type == CERTIFICATE){
                        cme_add_certificate(sdb,&signer->u.certificate,false);
                    }
                    else{
                        cme_add_certificate(sdb,&signer->u.certificates.buf+signer->u.certificates.len-1,false);
                    }
                    res = FOUND;
                }
                if(res != NOT_FOUND){
                    res = UNKNOWN_CERTIFICATE;
                    goto end;
                }
                if(send_cert != NULL){
                    if(signer->type == CERTIFICATE){
                        certificate_cpy(send_cert,&signer->u.certificate);
                    }
                    else{
                        certificate_cpy(send_cert,&signer->u.certificates.buf+signer->u.certificates.len-1);
                    }
                }
            }
            break;
        default:
            res = INVAID_INPUT;
            wave_error_printf("出现了其他类心 %s %d",__FILE__,__LINE__);
            goto end;
    }
    if(permissions.type == PSID_SSP ){
        for(i=0;i<permissions.u.psid_ssp_array.len.i++){
            if( (permissions.u.psid_ssp_array.buf+i)->psid == m_psid){
                string_cpy(ssp,&(permissions.u.psid_ssp_array.buf+i)->ssp);
                break;
            }
        } 
        if(i == permissions.u.psid_ssp_array.len ){
            res = INCONSISITENT_PERMISSIONS;
            goto end;
        }   
    }
    if(ssp != NULL && ssp.buf == NULL){
        else if(permissions.type == PSID_PRIORITY_SSP){
            for(i=0;i<permissions.u.psid_priority_ssp_array.len.i++){
                if( (permissions.u.psid_priority_ssp_array.buf+i)->psid == m_psid){
                    string_cpy(ssp,&(permissions.u.psid_priority_ssp_array.buf+i)->ssp);
                    break;
                }
            } 
            if(i == permissions.u.psid_priority_ssp_array.len ){
                res = INCONSISITENT_PERMISSIONS;
                goto end;
            }
        }
    }
    res = SUCCESS;
    goto end;
end:
    sec_data_free(&sdata);
    string_free(temp);
    cme_permissions_free(&permissions);
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
static inline void certificate_chain_add_cert(struct certificate_chain* certs,certificate* cert){
    certs->certs = (certificate*)realloc(sizeof(certificate)*certs->len+1);
    if(certs->certs == NULL){
        wave_malloc_error();
        return -1;
    }
    certs->len++;
    certificate_cpy(certs->certs+certs->len-1,cert);
    return 0;
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
