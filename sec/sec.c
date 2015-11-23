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
#include <math.h>
#include "../crypto/crypto.h"
#define INIT(m) memset(&m,0,sizeof(m))
#define US_TO_S 1000000
#define LOG_STD_DEV_BASE 1.134666

extern u32 certificate_request_permissions_max_length;//配置变量，配置证书申请最大的长度
extern struct region_type_array certificate_request_support_region_types;//配置变量，表示支持的类型
extern u32 certificate_request_rectangle_max_length;
extern u32 certificate_request_polygonal_max_length;

static int 
locate_header_ext(char *wsa, unsigned int *shift, unsigned int length, 
		struct wsa_header_ext *head_ext)
{
    unsigned char *eid_pos;
    unsigned int current_shift = *shift;
    eid element_id;
   
    INIT(*head_ext);

    while(current_shift < length){
        eid_pos = (unsigned char *)(wsa + current_shift);
        element_id = (eid)(*eid_pos);

        if(element_id != EID_REP_RATE && element_id != EID_TX_POWER && 
           element_id != EID_2D_LOCAT && element_id != EID_3D_LOCAT &&
           element_id != EID_ADV_ID && element_id != EID_CTRY_STR && 
           !((element_id >= 23 && element_id <= 127) || element_id >= 131) 
		   // to support self defined element id
           ){
			break;
        }

        switch(element_id){
            case EID_REP_RATE:
                head_ext->repeat_rate = eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_TX_POWER:
                head_ext->tx_power = (signed char *)eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_2D_LOCAT:
                head_ext->_2d_location = (char *)eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_3D_LOCAT:
                head_ext->_3d_location = (char *)eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_ADV_ID:
                head_ext->advertiser_id = (char *)eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_CTRY_STR:
                head_ext->country_string = (char *)eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            default:   
                //to support self defined ext.
                current_shift += (2 + ext_length(eid_pos));
                break;           
        }
    }

    *shift = current_shift;
    return 0;
}

static int 
locate_serv_ch_info_wra(char *wsa, unsigned int current_shift, unsigned int length, 
        struct service_info *serv_info, struct channel_info *ch_info, 
		struct wra *routing_adv)
{
    unsigned char serv_info_index = 255;
    unsigned char channel_info_index = 255;
    unsigned char wra_index = 255;
	/* element id range: 0 ~ 255 */
    unsigned char *eid_pos = NULL;  
    unsigned char *psid_pos = NULL;
    eid element_id;

    INIT(*routing_adv);

    while(current_shift < length){
        eid_pos = (unsigned char *)(wsa + current_shift);
        if(eid_pos == NULL)
            return -1;

        element_id = (eid)(*eid_pos);

        if(element_id != EID_SERVINFO && element_id != EID_PSC && 
           element_id != EID_IPV6ADDR && element_id != EID_SERVPORT &&
           element_id != EID_PROV_MAC && element_id != EID_RCPI_THR &&
           element_id != EID_WSAC_THR && element_id != EID_INTV_THR &&
           element_id != EID_CHANINFO && element_id != EID_EDCA_PARAM && 
           element_id != EID_CHAN_ACC && element_id != EID_WRA    && 
           element_id != EID_SEC_DNS  && element_id != EID_GT_MAC &&
           !((element_id >= 23 && element_id <= 127) || element_id >= 131) 
		   // to support self defined element id
          )
            return -1;

        switch(element_id){
            case EID_SERVINFO:
                serv_info_index ++;
				if(serv_info_index > 31){
					return -1;
				}
                psid_pos = eid_pos + 1;
                serv_info[serv_info_index].serv = (char *)eid_pos; 
                current_shift += (calcu_psid_length(psid_pos) + 3);

				if(serv_info_index)
					printk("\n");
                break;
            case EID_CHANINFO:
                channel_info_index ++;
				if(channel_info_index > 6){
					return -1;
				}
                ch_info[channel_info_index].channel = eid_pos;
                current_shift += 6;
				if(channel_info_index)
					printk("\n");
                break;
            case EID_WRA:         
                if(wra_index == 255)
                    wra_index = 0;
                routing_adv->wra = (char *)eid_pos;
                current_shift += 52;
				if(wra_index)
					printk("\n");
                break;
            case EID_PSC:
                if(serv_info_index != 255)        
                	//skip this service info extension fields with no preceding service info.
                    serv_info[serv_info_index].psc = (char *)eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_IPV6ADDR:
                if(serv_info_index != 255)
                    serv_info[serv_info_index].ipv6_addr = eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_SERVPORT:
                if(serv_info_index != 255)
                    serv_info[serv_info_index].serv_port = (__be16 *)eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_PROV_MAC:
                if(serv_info_index != 255)
                    serv_info[serv_info_index].prov_mac_addr = eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_RCPI_THR:
                if(serv_info_index != 255)
                    serv_info[serv_info_index].rcpi_thresh = (signed char *)eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_WSAC_THR:
                if(serv_info_index != 255)
                    serv_info[serv_info_index].wsa_count_thresh = eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_INTV_THR:
                if(serv_info_index != 255)
                    serv_info[serv_info_index].wsa_count_thresh_interv = eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_EDCA_PARAM:
                if(channel_info_index != 255)
                    ch_info[channel_info_index].edca_set = (char *)eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_CHAN_ACC:
                if(channel_info_index != 255)
                    ch_info[channel_info_index].channel_access = eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_SEC_DNS:
                if(wra_index != 255)
                    routing_adv->second_dns = (char *)eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            case EID_GT_MAC:
                if(wra_index != 255)
                    routing_adv->gateway_mac_addr = eid_pos;
                current_shift += (2 + ext_length(eid_pos));
                break;
            default:          
                current_shift += (2 + ext_length(eid_pos)); 
                //to support self defined element id
                break;            
            }
    }

    return 0;
}
static int extract_service_info(string *wsa, struct dot2_service_info_array *ser_infos){
    int ret = -1;
    int i = 0;
    unsigned int current_shift = 1;
    unsigned int ser_info_len = 0;
    struct wsa_header_ext header_ext;
    struct service_info *serv_info = NULL;
    struct channel_info *ch_info = NULL;
    struct wra wra;
    INIT(header_ext);
    INIT(wra);

    serv_info = malloc(sizeof(struct service_info)*32);
    if(!serv_info){
        wave_error_printf("分配内存失败");
        goto end;
    }

    ch_info = malloc(sizeof(struct channel_info)*32);
    if(!ch_info){
        wave_error_printf("分配内存失败");
        goto end;
    }

    if(!ser_infos){
        wave_error_printf("空指针，没有内容可以extract");
        goto end;
    }
    if(ser_infos->service_infos != NULL){
        wave_error_printf("serviceinfo array没有初始化");
        goto end;
    }

    locate_header_ext(wsa->buf, &current_shift, wsa->len, &header_ext);
    if(locate_serv_ch_info_wra(wsa->buf, current_shift, wsa->len,
                serv_info, ch_info, &wra)){
        wave_error_printf("解析service info失败");
        goto end;
    }
    
    struct service_info *ser_tmp  = NULL;
    char *tmp = NULL;
    unsigned char psid_len = 0;
    for(ser_tmp = &serv_info[0]; ser_tmp->serv != NULL; ser_tmp++)
        ser_info_len++;
    
    ser_infos->len = ser_info_len;
    ser_infos->service_infos = malloc(sizeof(struct dot2_service_info)*ser_info_len);
    if(!ser_infos->service_infos){
        wave_error_printf("内存分配失败");
        goto end;
    }
    for(i = 0; i < ser_info_len; i++){
        tmp = serv_info[i].serv;
        tmp++;
        psid_len = calcu_psid_length(tmp);
        char *le_psid = malloc(sizeof(char)*psid_len);
        if(!le_psid){
            wave_error_printf("分配内存失败");
            goto end;
        }
        memcpy(le_psid, tmp, psid_len);
        psid_be_2_le(le_psid, psid_len);
        memcpy(&ser_infos->service_infos[i].psid, le_psid, psid_len);
        free(le_psid);
        tmp += psid_len;

        memcpy(&ser_infos->service_infos[i].priority, tmp, 1);
    }
    ret = 0;
end:
    free(serv_info);
    free(ch_info);

    return ret;
}

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
static int hash_with_certificate(certificate* cert,string* message,string* hashed){
    switch(cert->version_and_type){
        case 2:
            if(cert->unsigned_certificate.holder_type  == ROOT_CA){
                switch(cert->unsigned_certificate.version_and_type.verification_key.algorithm){
                    case ECDSA_NISTP224_WITH_SHA224:
                       if( crypto_HASH224(message,hashed) ){
                            goto fail;
                       }  
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       if( crypto_HASH256(message,hashed))
                           goto fail;
                       break;
                    case ECIES_NISTP256:
                       wave_error_printf("这个是加密算法，怎么出现在了这个签名中");
                       goto fail;
                       break;
                }
            }
            else{
                switch(cert->unsigned_certificate.u.no_root_ca.signature_alg){
                    case ECDSA_NISTP224_WITH_SHA224:
                       if( crypto_HASH224(message,hashed) ){
                            goto fail;
                       }  
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       if( crypto_HASH256(message,hashed))
                           goto fail;
                       break;
                    case ECIES_NISTP256:
                       wave_error_printf("这个是加密算法，怎么出现在了这个签名中");
                       goto fail;
                       break;
                }
            }
            break;
        case 3:
             switch(cert->unsigned_certificate.u.no_root_ca.signature_alg){
                    case ECDSA_NISTP224_WITH_SHA224:
                       if( crypto_HASH224(message,hashed) ){
                            goto fail;
                       }  
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       if( crypto_HASH256(message,hashed))
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
    return 0;
fail:
    return -1;
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
                       if(crypto_ECDSA224_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           goto fail;
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       algorithm = ECDSA_NISTP256_WITH_SHA256;
                       if( crypto_HASH256(&encoded_tbs,&hashed_tbs))
                           goto fail;
                       if(crypto_ECDSA256_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           goto fail;
                       break;
                    case ECIES_NISTP256:
                       wave_error_printf("这个是加密算法，怎么出现在了这个签名中");
                       goto fail;
                       break;
                }
            }
            else{
                switch(cert.unsigned_certificate.u.no_root_ca.signature_alg){
                    case ECDSA_NISTP224_WITH_SHA224:
                       algorithm = ECDSA_NISTP224_WITH_SHA224;
                       if( crypto_HASH224(&encoded_tbs,&hashed_tbs) ){
                            goto fail;
                       } 
                       if(crypto_ECDSA224_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           goto fail; 
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       algorithm = ECDSA_NISTP256_WITH_SHA256;
                       if( crypto_HASH256(&encoded_tbs,&hashed_tbs))
                           goto fail;
                       if(crypto_ECDSA256_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           goto fail;
                       break;
                    case ECIES_NISTP256:
                       wave_error_printf("这个是加密算法，怎么出现在了这个签名中");
                       goto fail;
                       break;
                }
            }
            break;
        case 3:
             switch(cert.unsigned_certificate.u.no_root_ca.signature_alg){
                    case ECDSA_NISTP224_WITH_SHA224:
                       algorithm = ECDSA_NISTP224_WITH_SHA224;
                       if( crypto_HASH224(&encoded_tbs,&hashed_tbs) ){
                            goto fail;
                       }  
                       if(crypto_ECDSA224_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                            goto fail;
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       algorithm = ECDSA_NISTP256_WITH_SHA256;
                       if( crypto_HASH256(&encoded_tbs,&hashed_tbs))
                           goto fail;
                       if(crypto_ECDSA256_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
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
static inline int certificate_chain_add_cert(struct certificate_chain* certs,certificate* cert){
    certs->certs = (certificate*)realloc(certs->certs, sizeof(certificate)*certs->len+1);
    if(certs->certs == NULL){
        wave_malloc_error();
        return -1;
    }
    certs->len++;
    certificate_cpy(certs->certs+certs->len-1,cert);
    return 0;
}
result sec_encrypted_data(struct sec_db* sdb,content_type type,string* data,struct certificate_chain* certs,
                bool compressed,time64 overdue_crl_tolerance,
                
                string* encrypted_data,struct certificate_chain* failed_certs){
    if(encrypted_data == NULL || encrypted_data->buf != NULL ||failed_certs == NULL || 
            failed_certs->certs != NULL){
        wave_error_printf("参数有问题 %s %d",__FILE__,__LINE__);
    }
    
    result res = SUCCESS;
    struct certificate_chain enc_certs;
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
        string_free(&cert_string);
        temp_cert = certs->certs+i;
        if( certificate_2_string(temp_cert,&cert_string))
            goto end;
        res = cme_certificate_info_request(sdb,ID_CERTIFICATE,&cert_string, 
                            NULL,NULL,NULL,NULL,&next_crl_time,NULL,NULL);
        if(res != FOUND){
            res = FAIL_ON_SOME_CERTIFICATES;
            if(certificate_chain_add_cert(failed_certs,temp_cert))
                goto end;
        }
        else{
            time(&now);
            if(next_crl_time < now - overdue_crl_tolerance){
                wave_printf(MSG_WARNING,"crl没有获得，crl_next_time:%d  now:%d  over:%lld\n",
                        next_crl_time,now,overdue_crl_tolerance);
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
                        if( symm_alg != SYMM_ALGORITHM_NOT_SET && symm_alg != current_symm_alg){
                            res = FAIL_ON_SOME_CERTIFICATES;
                            if( certificate_chain_add_cert(failed_certs,temp_cert))
                                goto end;
                        }
                        else{
                            symm_alg = current_symm_alg;
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



result sec_secure_data_content_extration(struct sec_db* sdb,string* recieve_data,cmh cmh,

                            enum content_type *content_type,enum content_type *inner_type,string* data,
                            string* signed_data,psid *out_psid,
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
    enum content_type type;
    bool verified;
    psid m_psid;
    struct cme_permissions permissions;
    int i;

    INIT(sdata);
    INIT(temp);
    INIT(permissions);

    if(  string_2_sec_data(recieve_data,&sdata)){
        wave_error_printf("不能将受到的数据变为sdata %s %d",__FILE__,__LINE__);
        res = INVALID_INPUT;
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
                goto end;
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
            if(signed_data != NULL && signed_data->buf == NULL){
                if(signed_data_2_string(s_data,&signed_data)){
                    res = FAILURE;
                    wave_error_printf("编码失败 %s %d",__FILE__,__LINE__);
                    goto end;
                }
            }
            if(out_psid != NULL)
                *out_psid = m_psid;
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
                    if(expiry_time != NULL)
                        *expiry_time = s_data->unsigned_data.flags_content.exipir_time;
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

            signer = &s_data->signer;
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
                        cme_add_certificate(sdb,signer->u.certificates.buf+signer->u.certificates.len-1,false);
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
            res = INVALID_INPUT;
            wave_error_printf("出现了其他类心 %s %d",__FILE__,__LINE__);
            goto end;
    }
    
    if(ssp != NULL && ssp->buf == NULL){
        if(permissions.type == PSID_SSP ){
            for(i=0;i<permissions.u.psid_ssp_array.len;i++){
                if( (permissions.u.psid_ssp_array.buf+i)->psid == m_psid){
                    ssp->len = (permissions.u.psid_ssp_array.buf+i)->service_specific_permissions.len;
                    if( ssp->buf = (u8*)malloc(  ssp->len) ){
                        wave_malloc_error();
                        res = FAILURE;
                        goto end;
                    }
                    memcpy(ssp->buf,(permissions.u.psid_ssp_array.buf+i)->service_specific_permissions.buf,ssp->len);
                    break;
                }
            } 
            if(i == permissions.u.psid_ssp_array.len ){
                res = INCONSISITENT_PERMISSIONS;
                goto end;
            }   
        }
        else if(permissions.type == PSID_PRIORITY_SSP){
            for(i=0;i<permissions.u.psid_priority_ssp_array.len;i++){
                if( (permissions.u.psid_priority_ssp_array.buf+i)->psid == m_psid){
                    ssp->len = (permissions.u.psid_priority_ssp_array.buf+i)->service_specific_permissions.len;
                    if( ssp->buf = (u8*)malloc(  ssp->len) ){
                        wave_malloc_error();
                        res = FAILURE;
                        goto end;
                    }
                    memcpy(ssp->buf,(permissions.u.psid_priority_ssp_array.buf+i)->service_specific_permissions.buf,ssp->len);
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
    string_free(&temp);
    cme_permissions_free(&permissions);
    return res;
}

   
result sec_signed_data_verification(struct sec_db* sdb, cme_lsis lsis,psid* input_psid,content_type type,string* signed_data,
                            string* external_data, u32 max_cert_chain_len,bool detect_reply,bool check_generation_time,
                            time64 validity_period,time64_with_standard_deviation* generation_time,float generation_threshold,
                            time64 accepte_time,float accepte_threshold,bool check_expiry_time,time64 exprity_time,float exprity_threshold,
                            bool check_geneartion_location,two_d_location* location,u32 validity_distance,three_d_location* generation_location,
                            time64 overdue_crl_tolerance,
                            
                            struct time32_array *last_recieve_crl_times,
                            struct time32_array *next_expected_crl_times,
                            certificate* send_cert){

    result res = SUCCESS;

    struct certificate_chain  certs_chain,temp_certs_chain;
    struct cme_permissions_array permissions;
    struct geographic_region_array geo_scopes;
    struct verified_array verifieds;
    time64 expiry_time;
    time64_with_standard_deviation gen_time;
    two_d_location gen_loc,current_location;
    struct signed_data s_data;
    struct string string,digest;
    int i;
    time_t now;
    struct time32_array times;
    time32 start_validity;
    certificate* cert;
    struct cme_permissions* permission;
    psid m_psid;

    INIT(certs_chain);
    INIT(temp_certs_chain);
    INIT(permissions);
    INIT(geo_scopes);
    INIT(verifieds);
    INIT(s_data);
    INIT(expiry_time);
    INIT(gen_time);
    INIT(string);
    INIT(gen_loc);//这个初始化为0恰当不，，，，会有地理位之为0的点嘛？？？？
    INIT(times);
    INIT(digest);

    if( string_2_signed_data(signed_data, &s_data) ){
        wave_error_printf("signed_data解码失败 %s %d",__FILE__,__LINE__);
        res = INVALID_INPUT;
        goto end;
    }


    if( s_data.unsigned_data.tf & USE_GENERATION_TIME){
        gen_time.time = s_data.unsigned_data.flags_content.generation_time.time;
        gen_time.long_std_dev = s_data.unsigned_data.flags_content.generation_time.long_std_dev;
        if(generation_time != NULL){
            if(gen_time.time == generation_time->time){
                res = SUCCESS;
                goto next;
            }
            else{
                res = INVALID_INPUT;
                goto next;
            }

            if(gen_time.long_std_dev == generation_time->long_std_dev){
                res = SUCCESS;
                goto next;
            }
            else{
                res = INVALID_INPUT;
                goto next;
            }
        }
    }
    else if(generation_time != NULL){
        gen_time.time = generation_time->time;
        gen_time.long_std_dev = generation_time->long_std_dev;
    }

    if(s_data.unsigned_data.tf & EXPIRES){
        expiry_time = s_data.unsigned_data.flags_content.exipir_time;
        if(exprity_time != 0){
            if(expiry_time == exprity_time){
                res = SUCCESS;
                goto next;
            }
            else{
                res = INVALID_INPUT;
                goto next;
            }
        }
    }
    else if(exprity_time != 0){
        expiry_time = exprity_time;
    }

    if(s_data.unsigned_data.tf & USE_LOCATION){
        gen_loc.latitude = s_data.unsigned_data.flags_content.generation_location.latitude;
        gen_loc.longitude = s_data.unsigned_data.flags_content.generation_location.longitude;
        if(location != NULL){
            if(gen_loc.latitude == location->latitude){
                res = SUCCESS;
                goto next;
            }
            else{
                res = INVALID_INPUT;
                goto next;
            }
            if(gen_loc.longitude == location->longitude){
                res = SUCCESS;
                goto next;
            }
            else{
                res = INVALID_INPUT;
                goto next;
            }
        }
    }
    else if(location != NULL){
        gen_loc.longitude = location->longitude;
        gen_loc.latitude = location->latitude;
    }
    if(gen_loc.latitude == 0 && gen_loc.longitude == 0){
        res = INVALID_INPUT;
        goto next;
    }
    if(gen_loc.latitude == 900000001 && gen_loc.longitude == 1800000001){
        res = SENDER_LOCATION_UNAVAILABLE;
        goto next;
    }
next:
    if(res != SUCCESS){
        goto end;
    }
    if(gen_time.time != 0 && expiry_time != 0){
        if(expiry_time < gen_time.time){
            res = EXPIRTY_TIME_BEFORE_GENERATION_TIME;
            goto end;
        }
    }     

    switch(s_data.signer.type){
        case CERTIFICATE_DIGEST_WITH_ECDSAP224:
        case CERTIFICATE_DIGEST_WITH_ECDSAP256:
            string_free(&string);
            hashedid8_2_string(&s_data.signer.u.digest,&string);
            if( res = cme_construct_certificate_chain(sdb,ID_HASHEDID8,&string,NULL,false,max_cert_chain_len,
                         &certs_chain,&permissions,&geo_scopes,last_recieve_crl_times,&times,&verifieds) ){
                goto end;
            }
            if(next_expected_crl_times != NULL){
                next_expected_crl_times->times = (time32*)malloc(sizeof(time32) * times.len);
                if(next_expected_crl_times->times == NULL){
                    res = FAILURE;
                    wave_malloc_error();
                    goto end;
                }
                next_expected_crl_times->len = times.len;
                memcpy(next_expected_crl_times->times,times.times,sizeof(time32) * times.len);
            }
            break;
        case CERTIFICATE_CHAIN:
            temp_certs_chain.certs = (certificate*)malloc(sizeof(certificate) * s_data.signer.u.certificates.len);
            if(temp_certs_chain.certs == NULL){
                res = FAILURE;
                wave_malloc_error();
                goto end;
            }
            temp_certs_chain.len = s_data.signer.u.certificates.len;
            if( res = cme_construct_certificate_chain(sdb,ID_CERTIFICATE,NULL,&temp_certs_chain,false,max_cert_chain_len,
                        &certs_chain,&permissions,&geo_scopes,last_recieve_crl_times,next_expected_crl_times,&verifieds) ){
                goto end;
            }
        default:
            wave_error_printf("出现了不可能的直哦 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
    }

    if( res = sec_check_certificate_chain_consistency(sdb,&certs_chain,&permissions,&geo_scopes)){
        goto end;
    }
    time(&now);
    for(i=0;i<times.len;i++){
        if ( *(times.times+i) < now-overdue_crl_tolerance ){
             wave_printf(MSG_DEBUG,"next_expected_crl :%d  now :%d  overdue_crl_tolerance :%d",
                                *(times.times+i),now,overdue_crl_tolerance);
            res = OVERDUE_CRL;
            goto end;
        }
    }
    
    cert = certs_chain.certs;
    if( certificate_get_start_time(cert,&start_validity)){
            res = FAILURE;
            goto end;
    }
    if(gen_time.time != 0){ 
        if(gen_time.time / US_TO_S  <= start_validity){
            res = FUTURE_CERTIFICATE_AT_GENERATION_TIME;
            goto end;
        }
        if(gen_time.time / US_TO_S >= cert->unsigned_certificate.expiration){
            res = EXPIER_CERTIFICATE_AT_GENERATION_TIME;
            goto end;
        }
    }
    if(expiry_time != 0){
         if(expiry_time / US_TO_S <= start_validity){
            res = EXPIRY_DATE_TOO_EARLY;
            goto end;
         }
         if(expiry_time / US_TO_S >= cert->unsigned_certificate.expiration ){
            res = EXPIRY_DATE_TOO_LATE;
            goto end;
         }        
    }
    if(gen_loc.latitude != 0 && gen_loc.longitude != 0 && geo_scopes.regions != NULL){
        if(!two_d_location_in_geographic_region(&gen_loc,geo_scopes.regions)){
            res = SIGNATURE_GENERATED_OUTSIDE_CERTIFICATE_VALIDITY_REGION;
            goto end;
        }
    }
    switch(type){
        case SIGNED:
            m_psid = s_data.unsigned_data.u.type_signed.psid;
            break;
        case SIGNED_PARTIAL_PAYLOAD:
            m_psid = s_data.unsigned_data.u.type_signed_partical.psid;
            if(external_data != NULL){
                if(s_data.unsigned_data.u.type_signed_partical.ext_data.buf != NULL){
                    wave_printf(MSG_WARNING,"我觉得这里不应该会有直的，请核实一下，我觉得这里是一个潜在的bug的点，有可能是我对external_data这个理解有错误\
%s %d",__FILE__,__LINE__);
                    free(s_data.unsigned_data.u.type_signed_partical.ext_data.buf);
                }
                if( s_data.unsigned_data.u.type_signed_partical.ext_data.buf = (u8*)malloc(external_data->len) ){
                    wave_malloc_error();
                    res = FAILURE;
                    goto end;
                }
                memcpy(s_data.unsigned_data.u.type_signed_partical.ext_data.buf,external_data->buf,external_data->len);
            }
            break;
        case SIGNED_EXTERNAL_PAYLOAD:
            m_psid = s_data.unsigned_data.u.type_signed_external.psid;
            if(external_data != NULL){
                if(s_data.unsigned_data.u.type_signed_external.ext_data.buf != NULL){
                    wave_printf(MSG_WARNING,"我觉得这里不应该会有直的，请核实一下，我觉得这里是一个潜在的bug的点，有可能是我对external_data这个理解有错误\
 %s %d",__FILE__,__LINE__);
                    free(s_data.unsigned_data.u.type_signed_external.ext_data.buf);
                }
                if( s_data.unsigned_data.u.type_signed_external.ext_data.buf = (u8*)malloc(external_data->len) ){
                    wave_malloc_error();
                    res = FAILURE;
                    goto end;
                }
                memcpy(s_data.unsigned_data.u.type_signed_external.ext_data.buf,external_data->buf,external_data->len);
            }
            break;
        default:
            wave_error_printf("出现了不可能的类型 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
    }
    permission = permissions.cme_permissions; 
    switch(permission->type){
        case PSID:
            for(i=0;i<permission->u.psid_array.len;i++){
                if(m_psid == *(permission->u.psid_array.buf+i))
                    break;
            }
            if( i == permission->u.psid_array.len){
                res = UNAUTHORIZED_PSID;
                goto end;
            }
            break;
        case PSID_PRIORITY:
            for(i=0;i<permission->u.psid_priority_array.len;i++){
                if(m_psid == (permission->u.psid_priority_array.buf+i)->psid)
                    break;
            }
            if( i == permission->u.psid_priority_array.len){
                res = UNAUTHORIZED_PSID;
                goto end;
            }
            break;
        case PSID_PRIORITY_SSP:
            for(i=0;i<permission->u.psid_priority_ssp_array.len;i++){
                if(m_psid == (permission->u.psid_priority_ssp_array.buf+i)->psid)
                    break;
            }
            if( i == permission->u.psid_priority_ssp_array.len){
                res = UNAUTHORIZED_PSID;
                goto end;
            }
            break;
        default:
            wave_error_printf("出现了不可能出现的直 %s %d ",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
    }
    if(input_psid != NULL && *input_psid != m_psid){
        res = PSIDS_NOT_MATCH;
        goto end;
    }
    if( certs_chain.certs->unsigned_certificate.holder_type != SDE_ANONYMOUS &&
            certs_chain.certs->unsigned_certificate.holder_type != SDE_IDENTIFIED_NOT_LOCALIZED &&
            certs_chain.certs->unsigned_certificate.holder_type != SDE_IDENTIFIED_LOCALIZED){
        res = UNAUTHORIZED_CERTIFICATE_TYPE;
        goto end;
    }
    if(check_generation_time){
        if(generation_threshold > 1 || generation_threshold < 0 || accepte_threshold > 1|| accepte_threshold < 0){
            wave_error_printf("不要乱给参数撒 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
        }
        //请核实哈我写对没有
        if( normal_distribution_calculate_probability((float)generation_time->time,(float)pow(LOG_STD_DEV_BASE,generation_time->long_std_dev),
                            (float)generation_time->time,(float)(now*US_TO_S) > generation_threshold) > generation_threshold){
            res = DATA_EXPIRED_BASE_ON_EXPIRY_TIME;
            goto end;
        }
        //请核实下我写对没有
        if( normal_distribution_calculate_probability( (float)generation_time->time,(float)pow(LOG_STD_DEV_BASE,generation_time->long_std_dev),
                    (float)(now*US_TO_S),(float)generation_time->time+accepte_time) > accepte_threshold){
            res = FUTURE_DATA;
            goto end;
        }
    }
    if(check_expiry_time){
        if(exprity_threshold < 0 || exprity_threshold > 1){
            wave_error_printf("不要乱给参数撒 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
        }
        //请核实哈我写对没有,我认为本地的时间的绝对误差为1ms（我乱写的，我都不知道该为多少）
        if( normal_distribution_calculate_probability( (float)(now*US_TO_S),(float)(1000),(float)exprity_time,(float)now) > exprity_threshold){
            res = DATA_EXPIRED_BASE_ON_EXPIRY_TIME;
            goto end;
        }
    }
    string_free(&string);
    if( signed_data_2_string(&s_data,&string) ){
         res = FAILURE;
         goto end;
    }
    if( detect_reply){
        if( REPLAY ==  cme_reply_detection(sdb,lsis,&string) ){
            res = REPLAY;
        }
    }
    if(check_geneartion_location){
        get_current_location(&current_location);
        if( distance_with_two_d_location(&gen_loc,&current_location) > validity_distance + 0){//我没的localconf也不准备有
            res = OUT_OF_RANGE;
            goto end;
        }
    }
    
    if( hash_with_certificate((certs_chain.certs+certs_chain.len -1),&string,&digest) ){
            res = FAILURE;
            goto end;
    }
    res =  sec_verify_chain_signature(sdb,&certs_chain,&verifieds,&digest,&s_data.signature);
    if(res == SUCCESS){
        for(i=0;i<certs_chain.len;i++){
            cert = certs_chain.certs+i;
            cme_add_certificate(sdb,cert,true);
        }
        //协议上没说，这个我想应该是这样
        if(send_cert != NULL){
            certificate_cpy(send_cert,certs_chain.certs+certs_chain.len-1);
        }
    }
    
    goto end;
end:
    certificate_chain_free(&certs_chain);
    certificate_chain_free(&temp_certs_chain);
    cme_permissions_array_free(&permissions);
    geographic_region_array_free(&geo_scopes);
    verified_array_free(&verifieds);
    signed_data_free(&s_data);
    string_free(&string);
    string_free(&digest);
    time32_array_free(&times);
    return res;
    
    
}
result sec_crl_verification(struct sec_db* sdb,string* crl,time32 overdue_crl_tolerance,
        
                        struct time32_array* last_crl_times,
                        struct time32_array* next_crl_times,
                        certificate* send_cert){
    result res = SUCCESS;

    struct certificate_chain certs_chain,temp_certs_chain;
    struct cme_permissions_array permissions_array;
    struct geographic_region_array geo_scopes;
    struct verified_array verifieds;
    struct time32_array times;
    string digest,identifier,temp_string;
    time32 start_validity;
    hashedid8 cert_hashedid8;
    enum identifier_type id_type;
    certificate* cert;
    struct crl mycrl;
    time_t now;
    int i;

    INIT(certs_chain);
    INIT(temp_certs_chain);
    INIT(permissions_array);
    INIT(geo_scopes);
    INIT(verifieds);
    INIT(mycrl);
    INIT(identifier);
    INIT(times);
    INIT(cert_hashedid8);
    INIT(temp_string);

    if( string_2_crl(crl,&mycrl)){
        wave_error_printf("编码失败哦 %s %d",__FILE__,__LINE__);
        res = FAILURE;
        goto end;
    }
   if(mycrl.unsigned_crl.start_period > mycrl.unsigned_crl.issue_date){
        res = START_DATE_NOT_BEFORE_ISSUE_DATE;
        goto end;
   } 
   if(mycrl.unsigned_crl.issue_date > mycrl.unsigned_crl.next_crl){
        res = ISSUE_DATE_NOT_BEFORE_NEXT_CRL_DATE;
        goto end;
   }
   /*******************接下来的代码 和协议进行比较有较大的改动，请后面的人在核实下，**********/
   /**请参照
    * 协议  137 页d 和 100页 这里和协议的有矛盾。
    */
   if(mycrl.signer.type != CERTIFICATE_DIGEST_WITH_ECDSAP256){
        wave_error_printf("这里是协议一个没看懂的地方，感觉是矛盾的，这里很可能存在bug，请修改应该是什么算法 %s %d",__FILE__,__LINE__);
        res = INVAILD_CA_SIGNATURE_ALGORITHM;
        goto end;
   }

   switch(mycrl.signer.type){
       case CERTIFICATE_DIGEST_WITH_ECDSAP256:
       case CERTIFICATE_DIGEST_WITH_ECDSAP224:
           id_type = ID_HASHEDID8;
           hashedid8_2_string(&mycrl.signer.u.digest,&identifier);
           res = cme_construct_certificate_chain(sdb,id_type,&identifier,NULL,false,255,&certs_chain,&permissions_array,
                   &geo_scopes,last_crl_times,&times,&verifieds);
           
           break;
       case CERTIFICATE:
           id_type = ID_CERTIFICATE;
           temp_certs_chain.len = 1;
           if( temp_certs_chain.certs = (certificate*)malloc(sizeof(certificate) * 1)){
                wave_malloc_error();
                res = FAILURE;
                goto end;
           }
           certificate_cpy(temp_certs_chain.certs,&mycrl.signer.u.certificate);
           res = cme_construct_certificate_chain(sdb,id_type,NULL,&temp_certs_chain,false,255,&certs_chain,&permissions_array,
                   &geo_scopes,last_crl_times,&times,&verifieds);

           break;
       case CERTIFICATE_CHAIN:
           id_type = ID_CERTIFICATE;
           temp_certs_chain.len = mycrl.signer.u.certificates.len;
           if( temp_certs_chain.certs = (certificate*)malloc(sizeof(certificate) * temp_certs_chain.len)){
                wave_malloc_error();
                res = FAILURE;
                goto end;
           }
           for(i = 0;i<temp_certs_chain.len;i++){
                certificate_cpy(temp_certs_chain.certs+i,mycrl.signer.u.certificates.buf+i);
           }
           res = cme_construct_certificate_chain(sdb,id_type,NULL,&temp_certs_chain,false,255,&certs_chain,&permissions_array,
                   &geo_scopes,last_crl_times,&times,&verifieds);
           break;
       default:
           wave_error_printf("出现了不可能的指 %s %d",__FILE__,__LINE__);
           res = FAILURE;
           goto end;
   }
   /*******************和协议进行比较有较大改动,请核实哈*********************/
    if(next_crl_times != NULL){
        next_crl_times->len = times.len;
        if( next_crl_times->times = (time32*)malloc(times.len * sizeof(time32))){
            res = FAILURE;
            wave_malloc_error();
            goto end;
        }
        memcpy(next_crl_times->times,times.times,sizeof(time32) * times.len);
    }
    if(res != SUCCESS)
       goto end;
    res = sec_check_certificate_chain_consistency(sdb,&certs_chain,&permissions_array,&geo_scopes);
    if(res != SUCCESS)
       goto end;
    time(&now);
    for(i=0;i<times.len;i++){
        if(*(times.times+i) < now - overdue_crl_tolerance){
            res = OVERDUE_CRL;
            wave_printf(MSG_WARNING,"time : %d  now :%d overdue %d %s %d",*(times.times+i),now,overdue_crl_tolerance);
            goto end;
        }
    }    
    cert = certs_chain.certs;
    if( certificate_get_start_time(cert,&start_validity)){
        res = FAILURE;
        goto end;
    }
    if(mycrl.unsigned_crl.issue_date < start_validity){
        res = FUTURE_CERTIFICATE_AT_GENERATION_TIME;
        goto end;
    }
    if(mycrl.unsigned_crl.issue_date > cert->unsigned_certificate.expiration){
        res = EXPIER_CERTIFICATE_AT_GENERATION_TIME;
        goto end;
    }
    if(cert->unsigned_certificate.holder_type != SDE_CA && 
            cert->unsigned_certificate.holder_type != ROOT_CA &&
            cert->unsigned_certificate.holder_type != CRL_SIGNER){
        res = INVALID_CERTIFICATE_TYPE;
        goto end;
    }
    if(cert->unsigned_certificate.holder_type == CRL_SIGNER){
        for(i=0;i<cert->unsigned_certificate.scope.u.responsible_series.len;i++){
            if(mycrl.unsigned_crl.crl_series == 
                    *(cert->unsigned_certificate.scope.u.responsible_series.buf+i)){
                break;
            }
        }
        if(i == cert->unsigned_certificate.scope.u.responsible_series.len){
            res = CERTIFICATE_NOT_AUTHORIZED_FOR_SPECIFIED_CRL_SERIES;
            goto end;
        }
        if( hashedid8_equal(&cert->unsigned_certificate.u.no_root_ca.signer_id,&mycrl.unsigned_crl.ca_id) == false){
            res = CERTIFICATE_NOT_AUTHORIZED_TO_ISSUE_CRL_FOR_SPECIFIC_CA;
            goto end;
        }
    }
    else{
        if( certificate_2_hashedid8(cert,&cert_hashedid8)){
            res = FAILURE;
            goto end;
        }
        if(hashedid8_equal(&cert_hashedid8,&mycrl.unsigned_crl.ca_id) == false){
            res = WRONG_CA_ID_IN_CRL;
            goto end;
        }
    }

    if(unsigned_crl_2_string(&mycrl.unsigned_crl,&temp_string)){
        res = FAILURE;
        goto end;
    }
    if( hash_with_certificate(cert,&temp_string,&digest)){
        res = FAILURE;
        goto end;
    }
    res = sec_verify_chain_signature(sdb,&certs_chain,&verifieds,&digest,&mycrl.signature);
    if(res != SUCCESS)
        goto end;
    cme_add_crlinfo(sdb,mycrl.unsigned_crl.type,mycrl.unsigned_crl.crl_series,&mycrl.unsigned_crl.ca_id,
                            mycrl.unsigned_crl.crl_serial,mycrl.unsigned_crl.start_period,mycrl.unsigned_crl.issue_date,
                            mycrl.unsigned_crl.next_crl);
    
    switch(mycrl.unsigned_crl.type){
        case ID_ONLY:
            for(i=0;i<mycrl.unsigned_crl.u.entries.len;i++){
                cme_add_certificate_revocation(sdb,mycrl.unsigned_crl.u.entries.buf+i,&mycrl.unsigned_crl.ca_id,
                        mycrl.unsigned_crl.crl_series,0);
            }
            break;
        case ID_AND_EXPIRY:
            for(i=0;i<mycrl.unsigned_crl.u.expiring_entries.len;i++){
                cme_add_certificate_revocation(sdb,&((mycrl.unsigned_crl.u.expiring_entries.buf+i)->id),&mycrl.unsigned_crl.ca_id,
                        mycrl.unsigned_crl.crl_series,(mycrl.unsigned_crl.u.expiring_entries.buf+i)->expiry);
            }
            break;
        default:
            wave_error_printf("有来一个不可能的至，至少我现在不支持 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
    }
    goto end;
end:
    certificate_chain_free(&certs_chain);
    certificate_chain_free(&temp_certs_chain);
    cme_permissionsi_array_free(&permissions_array);
    geographic_region_array_free(&geo_scopes);
    verified_array_free(&verifieds);
    string_free(&digest);
    string_free(&identifier);
    crl_free(&mycrl);
    time32_array_free(&times);
    string_free(&temp_string);
    return res;
}
static bool cme_permissions_consisitent_with_cme_permissions(struct cme_permissions* permissions,
                    struct cme_permissions* ca_permissions){
    //这个函数的调用只能被证书申请调用，因为，我默认认为permissions的类型是psid_priority_ssp
    int i,j;
    for(i=0;i< permissions->u.psid_priority_ssp_array.len;i++){
            switch(ca_permissions->type){
            case PSID:
                for(j=0;j<ca_permissions->u.psid_array.len;j++){
                    if((permissions->u.psid_priority_ssp_array.buf+i)->psid == 
                            *(ca_permissions->u.psid_array.buf+j) ){
                        return false;
                    }
                }
                if(j == ca_permissions->u.psid_array.len){
                    return false; 
                }
                break;
            case PSID_PRIORITY:
                for(j=0;j<ca_permissions->u.psid_priority_array.len;j++){
                    if((permissions->u.psid_priority_ssp_array.buf+i)->psid == 
                            (ca_permissions->u.psid_priority_array.buf+j)->psid ){
                        return false;
                    }
                }
                if(j == ca_permissions->u.psid_priority_array.len){
                    return false;
                }
                break;
            case PSID_PRIORITY_SSP:
                for(j=0;j<ca_permissions->u.psid_priority_ssp_array.len;j++){
                    if((permissions->u.psid_priority_ssp_array.buf+i)->psid == 
                            (ca_permissions->u.psid_priority_ssp_array.buf+j)->psid ){
                        return false;
                    }
                }
                if(j == ca_permissions->u.psid_priority_ssp_array.len){
                    return false;
                }
                break;
            case PSID_SSP:
                for(j=0;j<ca_permissions->u.psid_ssp_array.len;j++){
                    if((permissions->u.psid_priority_ssp_array.buf+i)->psid == 
                            (ca_permissions->u.psid_ssp_array.buf+j)->psid ){
                        return false;
                    }
                }
                if(j == ca_permissions->u.psid_ssp_array.len){
                    return false;
                }
                break;
            default:
                wave_error_printf("出现了不可能的指 %s %d",__FILE__,__LINE__);
                return false;
        }
    }
    return true;

}

result sec_get_certificate_request(struct sec_db* sdb,signer_identifier_type type,
                cmh cmh,
                holder_type cert_type,
                enum transfer_type transfer_type,
                struct cme_permissions* permissions,
                string* identifier,
                geographic_region* region,
                bool start_validity,
                bool life_time_duration,
                time32 start_time,
                time32 expiry_time,
                public_key* veri_pub_key,
                public_key* enc_pub_key,
                public_key* respon_enc_key,
                certificate* ca_cert,
                
                string* cert_request_string,
                certid10* request_hash){
    int i,j;
    result res = SUCCESS;
    struct cme_permissions ca_permissions,csr_cert_permissions;
    holder_type_flags ca_holder_types,csr_cert_holder_types;
    geographic_region ca_scope,csr_cert_scope;
    certificate csr_cert;
    string temp_string,pubkey_x,pubkey_y,prikey,hashed_string,signature_string;
    certificate_request cert_request;
    tobesigned_certificate_request* tbs;
    pk_algorithm algorithm = 100;
    elliptic_curve_point point;
    struct certificate_chain cert_chain;
    time_t now;

    INIT(ca_permissions);
    INIT(point);
    INIT(csr_cert_permissions);
    INIT(ca_holder_types);
    INIT(csr_cert_holder_types);
    INIT(ca_scope);
    INIT(csr_cert_scope);
    INIT(csr_cert);
    INIT(temp_string);
    INIT(pubkey_x);
    INIT(pubkey_y);
    INIT(prikey);
    INIT(hashed_string);
    INIT(signature_string);
    INIT(cert_request);
    INIT(cert_chain);
    
    if(type == CERTIFICATE){
        if( find_cert_prikey_by_cmh(sdb,cmh,&csr_cert,&prikey)){
            res = FAILURE;
            goto end;
        }
        if(csr_cert.version_and_type != 2){
            res = FAILURE;
            wave_error_printf("你叫我怎么提取认证钥匙 %s %d",__FILE__,__LINE__);
            goto end;
        }
        algorithm = csr_cert.unsigned_certificate.version_and_type.verification_key.algorithm;
    }
    if( certificate_2_string(ca_cert,&temp_string)){
        res = FAILURE;
        goto end;
    }
    res = cme_certificate_info_request(sdb,ID_CERTIFICATE,&temp_string,NULL,&ca_permissions,
                        &ca_scope,NULL,NULL,NULL,NULL);
    if(ca_cert->unsigned_certificate.holder_type != ROOT_CA){
        wave_error_printf("我个人觉得应该不会出现这个提示，如果出现请核实下是否是我的理解有错误 因为这个后后面的代码香光 %s %d",__FILE__,__LINE__);
        res = FAILURE;
        goto end;
    }
    switch(ca_cert->unsigned_certificate.holder_type){
        case ROOT_CA:
            ca_holder_types = ca_cert->unsigned_certificate.scope.u.root_ca_scope.permitted_holder_types;
            break;
        case SDE_CA:
        case SDE_ENROLMENT:
            ca_holder_types = ca_cert->unsigned_certificate.scope.u.sde_ca_scope.permitted_holder_types;
            break;
        default:
            wave_error_printf("这个类型就没有这个指，请核实哈 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
    }
    if(res != SUCCESS)
        goto end;
    if(ca_holder_types & cert_type == 0){
        res = INCONSISTENT_CA_PERMISSIONS;
        goto end;
    }
    if( permissions->type != PSID_PRIORITY_SSP){
        wave_error_printf("我觉得这个地方应该只有这种类型，我个人现在认为证书的申请只有cmp能调用 %s %d ",__FILE__,__LINE__);
        res = FAILURE;
        goto end;
    }
    if( cme_permissions_consisitent_with_cme_permissions(permissions,&ca_permissions) == false){
        res = INCONSISTENT_CA_PERMISSIONS;
        goto end;
    }
   
    if( geographic_region_in_geographic_region(region,&ca_scope) == false){
        res = INCONSISTENT_CA_PERMISSIONS;
        goto end;
    }
    if(type == CERTIFICATE){
        string_free(&temp_string);
        if( certificate_2_string(&csr_cert,&temp_string)){
            res = FAILURE;
            goto end;
        }
        if( res = cme_certificate_info_request(sdb,ID_CERTIFICATE,&temp_string,NULL,&csr_cert_permissions,
                    &csr_cert_scope,NULL,NULL,NULL,NULL)){
            goto end;
        }
        switch(csr_cert.unsigned_certificate.holder_type){
            case ROOT_CA:
                csr_cert_holder_types = csr_cert.unsigned_certificate.scope.u.root_ca_scope.permitted_holder_types;
                break;
            case SDE_CA:
            case SDE_ENROLMENT:
                csr_cert_holder_types = csr_cert.unsigned_certificate.scope.u.sde_ca_scope.permitted_holder_types;
                break;
            default:
                wave_error_printf("这个类型就没有这个指，请核实哈 %s %d",__FILE__,__LINE__);
                res = FAILURE;
                goto end;
        }
        if(csr_cert_holder_types & cert_type == 0){
            res = INCONSISTENT_CA_PERMISSIONS;
            goto end;
        }
        if(cme_permissions_consisitent_with_cme_permissions(permissions,&csr_cert_permissions) == false){
            res = INCONSISTENT_CA_PERMISSIONS;
            goto end;
        }
        if( geographic_region_in_geographic_region(region,&csr_cert_scope) == false){
            res = INCONSISTENT_CA_PERMISSIONS;
            goto end;
        } 
    }
    if( type == SELF){
        if( find_keypaire_by_cmh(sdb,cmh,&pubkey_x,&pubkey_y,&prikey,&algorithm)){
            wave_error_printf("钥匙没有找到 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
        }
        if( veri_pub_key->algorithm != algorithm ){
            res = INCONSISITENT_KEYS_IN_REQUEST;
            goto end;
        }
        switch(algorithm){
            case ECDSA_NISTP256_WITH_SHA256:
                for(i=0;i<pubkey_x.len;i++){
                    if( *(veri_pub_key->u.public_key.x.buf +i) != *(pubkey_x.buf+i)){
                        break;
                    }
                }
                if( i == pubkey_x.len){
                    res = INCONSISITENT_KEYS_IN_REQUEST;
                    goto end;
                }
                //y怎么比较 怎么压缩，怎么解压
                break;
            case ECDSA_NISTP224_WITH_SHA224:
                for(i=0;i<pubkey_x.len;i++){
                    if( *(veri_pub_key->u.public_key.x.buf +i) != *(pubkey_x.buf+i))
                        break;
                }
                if( i == pubkey_x.len){
                    res = INCONSISITENT_KEYS_IN_REQUEST;
                    goto end;
                }
                //y怎么比较 怎么压缩，怎么解压
                break;
            default:
               wave_error_printf("出现了不可能的指 %s %d",__FILE__,__LINE__);
               res = FAILURE;
               goto end; 
        }
    }
    switch(permissions->type){
        case PSID:
            if(permissions->u.psid_array.len > certificate_request_permissions_max_length){
                wave_error_printf("申请的长度超出了我们规定的最大的长度 %s %d",__FILE__,__LINE__);
                res = TOO_MANY_ENTRIES_IN_PERMISSON_ARRAY;
                goto end;
            }
            break;
        case PSID_PRIORITY_SSP:
            if( permissions->u.psid_priority_ssp_array.len > certificate_request_permissions_max_length){
                wave_error_printf("申请的长度超出了我们规定的最大的长度 %s %d",__FILE__,__LINE__);
                res = TOO_MANY_ENTRIES_IN_PERMISSON_ARRAY;
                goto end;
            }
            break;
        case PSID_SSP:
            if( permissions->u.psid_ssp_array.len > certificate_request_permissions_max_length){
                wave_error_printf("申请的长度超出了我们规定的最大的长度 %s %d",__FILE__,__LINE__);
                res = TOO_MANY_ENTRIES_IN_PERMISSON_ARRAY;
                goto end;
            }
            break;
        case PSID_PRIORITY:
            if( permissions->u.psid_priority_array.len > certificate_request_permissions_max_length){
                wave_error_printf("申请的长度超出了我们规定的最大的长度 %s %d",__FILE__,__LINE__);
                res = TOO_MANY_ENTRIES_IN_PERMISSON_ARRAY;
                goto end; 
            }
            break;
        default:
            wave_error_printf("出现了不可能的指 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
    }
    for(i=0;i<certificate_request_support_region_types.len;i++){
        if( region->region_type == *(certificate_request_support_region_types.types+i) ){
            break;
        }
    }
    if( i == certificate_request_support_region_types.len ){
        wave_error_printf("申请的地址类型不是我们支持的类型 %s %d",__FILE__,__LINE__);
        res = UNSUPPORTED_REGION_TYPE_IN_CERTIFICATE;
        goto end;
    }
    if(region->region_type == RECTANGLE){
        if( region->u.rectangular_region.len > certificate_request_rectangle_max_length){
            wave_error_printf("支持的RECTANGLE的长度超出了我们规定的最大长度 %s %d",__FILE__,__LINE__);
            res = TOO_MANY_ENTRIES_IN_RECTANGULAR_GEOGRAPHIC_SCOPE;
            goto end;
        }
    }
    if(region->region_type == POLYGON){
        if( region->u.polygonal_region.len > certificate_request_polygonal_max_length){
            wave_error_printf("支持的polygon的长度超出了我们规定的最大长度 %s %d",__FILE__,__LINE__);
            res = TOO_MANY_ENTRIES_IN_POLYGONAL_GEOGRAPHIC_SCOPE;
            goto end;
        }
    }
    tbs = &cert_request.unsigned_csr;
    tbs->version_and_type = transfer_type;
    if(start_validity){
        tbs->cf |= USE_START_VALIDITY;
        tbs->flags_content.start_validity = start_time;
    }
    if(life_time_duration){
        tbs->cf |= LIFETIME_IS_DURATION;
        tbs->flags_content.lifetime = expiry_time - start_time;
    }
    if(enc_pub_key != NULL){
        tbs->cf |= ENCRYPTION_KEY;
        public_key_cpy(&tbs->flags_content.encryption_key,enc_pub_key); 
    }
    time(&now);
    tbs->request_time = now;
    tbs->holder_type = cert_type;
    switch(cert_type){
        case ROOT_CA:
            if(identifier != NULL)
                wave_printf(MSG_WARNING,"这里没有identifier 即使你填写也没用 %s %d",__FILE__,__LINE__);
            wave_error_printf("这里应该不会出现这个指 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
            //tbs->type_specific_data.u.root_ca_scope;
            break;
        case SDE_CA:
        case SDE_ENROLMENT:
            wave_error_printf("这里应该不会出现这个指 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
            //tbs->type_specific_data.u.sde_ca_scope;
            break;
        case SDE_IDENTIFIED_NOT_LOCALIZED:
            wave_error_printf("这里应该不会出现这个指 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
            //tbs->type_specific_data.u.id_non_loc_scope;
            break;
        case SDE_ANONYMOUS:
            wave_error_printf("这里应该不会出现这个指 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
            //tbs->type_specific_data.u.anonymous_scope;
            break;
        case WSA:
            if(identifier != NULL)
                wave_printf(MSG_WARNING,"这里没有identifier 即使你填写也没用 %s %d",__FILE__,__LINE__);
            tbs->type_specific_data.u.wsa_scope.permissions.type = ARRAY_TYPE_SPECIFIED;
            tbs->type_specific_data.u.wsa_scope.permissions.u.permissions_list.len =
                        permissions->u.psid_priority_ssp_array.len;
            if( tbs->type_specific_data.u.wsa_scope.permissions.u.permissions_list.buf = 
                        (psid_priority_ssp*)malloc(sizeof(psid_priority_ssp) * permissions->u.psid_priority_ssp_array.len)){
                wave_malloc_error();
                res = FAILURE;
                goto end;
            }
            memcpy(tbs->type_specific_data.u.wsa_scope.permissions.u.permissions_list.buf,
                        permissions->u.psid_priority_ssp_array.buf,sizeof(psid_priority_ssp) * permissions->u.psid_priority_ssp_array.len);

            if(region != NULL)
                wave_printf(MSG_WARNING,"你填写了region 但是我们这里没有填写进去 %s %d",__FILE__,__LINE__);
            break;
        case WSA_CA:
        case WSA_ENROLMENT:
            wave_error_printf("这里应该不会出现这个指 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
            //tbs->type_specific_data.u.wsa_ca_scope;
            break;
        default:
            wave_error_printf("出现了我觉得不可能的指 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
    }
    public_key_cpy(&tbs->verification_key,veri_pub_key);
    public_key_cpy(&tbs->response_encryption_key,respon_enc_key);

    string_free(&temp_string);
    if( tobesigned_certificate_request_2_string(tbs,&temp_string)){
        res = FAILURE;
        goto end;
    }
    switch(algorithm){
        case ECDSA_NISTP256_WITH_SHA256:
            crypto_HASH256(&temp_string,&hashed_string);
            crypto_ECDSA256_sign_message(&hashed_string,&prikey,&signature_string);
            break;
        case ECDSA_NISTP224_WITH_SHA224:
            crypto_HASH224(&temp_string,&hashed_string);
            crypto_ECDSA224_sign_message(&hashed_string,&prikey,&signature_string);
        default:
            wave_error_printf("出现了不可能的指 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
    }
    
    cert_request.signer.type = type;
    if(type == CERTIFICATE){
        certificate_cpy(&cert_request.signer.u.certificate,&csr_cert);
    }
    if( cert_request.signature.u.ecdsa_signature.s.buf = (u8*)malloc(signature_string.len) ){
        wave_malloc_error();
        res = FAILURE;
        goto end;
    }
    memcpy(cert_request.signature.u.ecdsa_signature.s.buf,signature_string.buf,signature_string.len);
    cert_request.signature.u.ecdsa_signature.s.len = signature_string.len;

    if(type == CERTIFICATE){
        if( certificate_get_elliptic_curve_point(&csr_cert,&point)){
            res = FAILURE;
            goto end;
        }
    }
    else if(type == SELF){
        point.type = UNCOMPRESSED;
        point.x.len = pubkey_x.len;
        point.u.y.len = pubkey_y.len;
        if( point.x.buf = (u8*)malloc(point.x.len)  ){
            wave_malloc_error();
            res = FAILURE;
            goto end;
        }
        if( point.u.y.buf = (u8*)malloc(point.u.y.len)){
            wave_malloc_error();
            res = FAILURE;
            goto end;
        }
        memcpy(point.x.buf,pubkey_x.buf,pubkey_x.len);
        memcpy(point.u.y.buf,pubkey_y.buf,pubkey_y.len);
    }
    else{
        wave_error_printf("怎么半  应该不会有其他指的吧  %s %d",__FILE__,__LINE__);
        res = FAILURE;
        goto end;
    }
    elliptic_curve_point_cpy(&cert_request.signature.u.ecdsa_signature.r,&point);
    
    string_free(&temp_string);
    string_free(&hashed_string);
    certificate_request_2_string(&cert_request,&temp_string);
    crypto_HASH256(&temp_string,&hashed_string);

    if(request_hash != NULL){    
        memcpy(request_hash->certid10,hashed_string.buf + hashed_string.len - 10,10);
    }
    cert_chain.len = 1;
    if( cert_chain.certs = (certificate*)malloc(sizeof(certificate) * 1) ){
        wave_malloc_error();
        res = FAILURE;
        goto end;
    }
    certificate_cpy(cert_chain.certs,ca_cert);
    if( res = sec_encrypted_data(sdb,CERTIFICATE_REQUEST,&temp_string,&cert_chain,true,0,cert_request_string,NULL)){
        goto end;
    }
    goto end;
end:
    cme_permissions_free(&ca_permissions);
    cme_permissions_free(&csr_cert_permissions);
    geographic_region_free(&ca_scope);
    geographic_region_free(&csr_cert_scope);
    certificate_free(&csr_cert);
    string_free(&temp_string);
    string_free(&pubkey_x);
    string_free(&pubkey_y);
    string_free(&prikey);
    string_free(&signature_string);
    string_free(&hashed_string);
    elliptic_curve_point_free(&point);
    certificate_request_free(&cert_request);
    certificate_chain_free(&cert_chain);
    return res;
}
result sec_certficate_response_processing(struct sec_db* sdb,cmh cmh,string* data,
                
                content_type *type,
                certid10* request_hash,
                certificate_request_error_code* error,
                certificate* cert,
                string* rec_value,
                bool *ack_request){
    result res;
    content_type m_type;
    encrypted_data* ed=NULL;
    tobe_encrypted_certificate_response tbscr;
    sec_data s_data;
    string temp_string,de_data;
    tobe_encrypted_certificate_request_error cert_req_error;
    tobe_encrypted_certificate_response cert_resp;

    INIT(tbscr);
    INIT(s_data);
    INIT(temp_string);
    INIT(de_data);
    INIT(cert_req_error);
    INIT(cert_resp);

    if( string_2_sec_data(data,&s_data)){
        wave_error_printf("解码 失败 %s %d",__FILE__,__LINE__);
        res = FAILURE;
        goto end;
    }
    if(s_data.type == ENCRYPTED){
        ed = &s_data.u.encrypted_data;
    }
    else{
        wave_error_printf("这个数据不应该出现其他类型哈 %s %d",__FILE__,__LINE__);
        res = FAILURE;
        goto end;
    }
    if( encrypted_data_2_string(ed,&temp_string) ){
        res = FAILURE;
        goto end;
    }
    if( res = sec_decrypt_data(sdb,&temp_string,cmh, &m_type,&de_data)){
        goto end;
    }
    if( type != NULL)
        *type = m_type;
    if( m_type != CERTIFICATE_RESPONSE && m_type != CERTIFICATE_REQUSET_ERROR){
        res = UNEXPECTED_TYPE;
        wave_error_printf("出现了不可能的指 %s %d",__FILE__,__LINE__);
        goto end;
    }
    if(m_type == CERTIFICATE_REQUSET_ERROR){
        if( string_2_tobe_encrypted_certificate_request_error(&de_data,&cert_req_error)){
            res = FAILURE;
            wave_error_printf("解码错误 %s %d",__FILE__,__LINE__);
            goto end;
        }
        res = sec_certificate_request_error_verification(sdb,&cert_req_error);
        if(res != SUCCESS)
            goto end;
        if(request_hash != NULL){
            memcpy(request_hash->certid10,cert_req_error.request_hash,10);
        }
       if( error != NULL){
           *error = cert_req_error.reason;
       }
       goto end;
    }
    if(m_type == CERTIFICATE_RESPONSE){
        if(string_2_tobe_encrypted_certificate_response(&de_data,&cert_resp)){
            res = FAILURE;
            wave_error_printf("解码错误 %s %d",__FILE__,__LINE__);
            goto end;
        }
        res = sec_certificate_response_verification(sdb,&cert_resp);
        if(res != SUCCESS)
            goto end;
        if(cert != NULL){
            certificate_cpy(cert,cert_resp.certificate_chain.buf);
        }
        if(rec_value != NULL){
            if(s_data.type == 3){
                rec_value->len = cert_resp.u.recon_priv.len;
                if( rec_value->buf = (u8*)malloc(rec_value->len)){
                    res = FAILURE;
                    wave_malloc_error();
                    goto end;
                }
                memcpy(rec_value->buf,cert_resp.u.recon_priv.buf,rec_value->len);
            }
            else{
                res = FAILURE;
                wave_error_printf("出现了我认为不该出现的指 %s %d",__FILE__,__LINE__);
                goto end;
            }
        }
        if(ack_request != NULL){
            if(cert_resp.f == 0){
                *ack_request = true;
            }
            else{
                *ack_request = false;
            }
        }
        goto end;
    }
end:
    tobe_encrypted_certificate_response_free(&tbscr);
    sec_data_free(&s_data);
    string_free(&temp_string);
    string_free(&de_data);
    tobe_encrypted_certificate_response_free(&cert_req_error);
    tobe_encrypted_certificate_request_error_free(&cert_resp);
    return res;
}
//未测
result sec_signed_wsa(struct sec_db* sdb,string* data,serviceinfo_array* permissions,time32 life_time,string* signed_wsa){
    if(!signed_wsa){
        wave_error_printf("返回指针为空，没有内容可以填充");
        return FAILURE;
    }
    if(signed_wsa->buf != NULL){
        wave_error_printf("signed wsa中的buf指针没有初始化");
        return FAILURE;
    }
    result ret = FAILURE;
    struct certificate_chain chain;
    string permission_indices;
    cmh cmh;
    two_d_location td_location;
    sec_data sec_data;
    certificate cert;
    string privatekey, encoded_tbs, hashed_tbs, signed_tbs;
    pk_algorithm algorithm = PK_ALGOTITHM_NOT_SET;//这里让他等于一个不可能的指

    INIT(signed_tbs);
    INIT(encoded_tbs);
    INIT(hashed_tbs);
    INIT(privatekey);
    INIT(cert);
    INIT(chain);
    INIT(permission_indices);
    INIT(td_location);
    INIT(sec_data);

    if(get_current_location(&td_location)){
        wave_error_printf("获取当前地理位置失败");
        ret = FAILURE;
        goto fail;
    }

    ret = pssme_cryptomaterial_handle(sdb, permissions, &td_location, &permission_indices, &cmh, &chain);
    if(ret != SUCCESS)
        goto fail;

    //填充tobesigned_wsa中的permission_indices
    sec_data.u.signed_wsa.unsigned_wsa.permission_indices.len = permission_indices.len;
    sec_data.u.signed_wsa.unsigned_wsa.permission_indices.buf = malloc(sizeof(u8)*permission_indices.len);
    if(sec_data.u.signed_wsa.unsigned_wsa.permission_indices.buf == NULL){
        wave_error_printf("分配内存失败");
        ret = FAILURE;
        goto fail;
    }
    memcpy(sec_data.u.signed_wsa.unsigned_wsa.permission_indices.buf, permission_indices.buf, permission_indices.len*sizeof(u8));
    
    //设置use_location和use_generation_time flag
    sec_data.u.signed_wsa.unsigned_wsa.tf = sec_data.u.signed_wsa.unsigned_wsa.tf & USE_GENERATION_TIME & USE_LOCATION;

    //填充data
    sec_data.u.signed_wsa.unsigned_wsa.data.len = data->len;
    sec_data.u.signed_wsa.unsigned_wsa.data.buf = malloc(sizeof(u8)*data->len);
    if(sec_data.u.signed_wsa.unsigned_wsa.data.buf == NULL){
        wave_error_printf("分配内存失败");
        ret = FAILURE;
        goto fail;
    }
    memcpy(sec_data.u.signed_wsa.unsigned_wsa.data.buf, data->buf, data->len*sizeof(u8));

    //对generation_time和generation_location编码填充，暂时没有

    sec_data.u.signed_wsa.unsigned_wsa.expire_time = life_time;
    sec_data.u.signed_wsa.unsigned_wsa.tf = sec_data.u.signed_wsa.unsigned_wsa.tf & EXPIRES;


    //填充signature
    if(tobesigned_wsa_2_string(&sec_data.u.signed_wsa.unsigned_wsa, &encoded_tbs)){
        wave_error_printf("编码失败");
        ret = FAILURE;
        goto fail;
    }
    if(find_cert_prikey_by_cmh(sdb, cmh, &cert, &privatekey)){
        ret = FAILURE;
        goto fail;
    }
    switch(cert.version_and_type){
        case 2:
            if(cert.unsigned_certificate.holder_type  == ROOT_CA){
                switch(cert.unsigned_certificate.version_and_type.verification_key.algorithm){
                    case ECDSA_NISTP224_WITH_SHA224:
                        algorithm = ECDSA_NISTP224_WITH_SHA224;
                       if( crypto_HASH224(&encoded_tbs,&hashed_tbs) ){
                           ret = FAILURE;
                            goto fail;
                       }  
                       if(crypto_ECDSA224_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           ret = FAILURE;
                           goto fail;
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       algorithm = ECDSA_NISTP256_WITH_SHA256;
                       if( crypto_HASH256(&encoded_tbs,&hashed_tbs))
                           ret = FAILURE;
                           goto fail;
                       if(crypto_ECDSA256_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           ret = FAILURE;
                           goto fail;
                       break;
                    case ECIES_NISTP256:
                       wave_error_printf("这个是加密算法，怎么出现在了这个签名中");
                       ret = FAILURE;
                       goto fail;
                       break;
                }
            }
            else{
                switch(cert.unsigned_certificate.u.no_root_ca.signature_alg){
                    case ECDSA_NISTP224_WITH_SHA224:
                       algorithm = ECDSA_NISTP224_WITH_SHA224;
                       if( crypto_HASH224(&encoded_tbs,&hashed_tbs) ){
                           ret = FAILURE;
                            goto fail;
                       } 
                       if(crypto_ECDSA224_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           ret = FAILURE;
                           goto fail; 
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       algorithm = ECDSA_NISTP256_WITH_SHA256;
                       if( crypto_HASH256(&encoded_tbs,&hashed_tbs))
                           ret = FAILURE;
                           goto fail;
                       if(crypto_ECDSA256_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           ret = FAILURE;
                           goto fail;
                       break;
                    case ECIES_NISTP256:
                       wave_error_printf("这个是加密算法，怎么出现在了这个签名中");
                       ret = FAILURE;
                       goto fail;
                       break;
                }
            }
            break;
        case 3:
             switch(cert.unsigned_certificate.u.no_root_ca.signature_alg){
                    case ECDSA_NISTP224_WITH_SHA224:
                       algorithm = ECDSA_NISTP224_WITH_SHA224;
                       if( crypto_HASH224(&encoded_tbs,&hashed_tbs) ){
                           ret = FAILURE;
                            goto fail;
                       }  
                       if(crypto_ECDSA224_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           ret = FAILURE;
                            goto fail;
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       algorithm = ECDSA_NISTP256_WITH_SHA256;
                       if( crypto_HASH256(&encoded_tbs,&hashed_tbs))
                           ret = FAILURE;
                           goto fail;
                       if(crypto_ECDSA256_sign_message(&hashed_tbs,&privatekey,&signed_tbs))
                           ret = FAILURE;
                            goto fail;
                       break;
                    case ECIES_NISTP256:
                       wave_error_printf("这个是加密算法，怎么出现在了这个签名中");
                       ret = FAILURE;
                       goto fail;
                       break;
            } 
            break;
        default:
            wave_error_printf("出现了不可能出现的指 %s %d ",__FILE__,__LINE__);
            ret = FAILURE;
            goto fail;
    }
    //create and encode a signedwsa
    sec_data.u.signed_wsa.signer.type = CERTIFICATE_CHAIN;
    sec_data.u.signed_wsa.signer.u.certificates.len = chain.len;
    sec_data.u.signed_wsa.signer.u.certificates.buf = malloc(sizeof(certificate)*chain.len);
    if(!sec_data.u.signed_wsa.signer.u.certificates.buf){
        wave_error_printf("分配内存失败!");
        ret = FAILURE;
        goto fail;
    }
    int i = 0;
    for(i = 0; i < chain.len; i++)
        certificate_cpy(&sec_data.u.signed_wsa.signer.u.certificates.buf[i], &chain.certs[i]);
    
    sec_data.u.signed_wsa.signature.u.ecdsa_signature.s.len = signed_tbs.len;
    sec_data.u.signed_wsa.signature.u.ecdsa_signature.s.buf = malloc(signed_tbs.len);
    if(!sec_data.u.signed_wsa.signature.u.ecdsa_signature.s.buf){
        wave_malloc_error();
        ret = FAILURE;
        goto fail;
    }
    memcpy(sec_data.u.signed_wsa.signature.u.ecdsa_signature.s.buf, signed_tbs.buf, signed_tbs.len);

    //填充1609dot2结构体
    sec_data.protocol_version = 2;                                  
    sec_data.type = SIGNED_WSA;                                
    if(sec_data_2_string(&sec_data, signed_wsa)){                                  
        wave_error_printf("sec data 编码失败");                                  
        ret = FAILURE;                                  
        goto fail;                                  
    }                                  
    ret = SUCCESS;
fail:                                  
    certificate_chain_free(&chain);                                  
    string_free(&permission_indices);                                  
    two_d_location_free(&td_location);                                  
    sec_data_free(&sec_data);                                  
    string_free(&privatekey);
    string_free(&encoded_tbs);
    string_free(&hashed_tbs);
    string_free(&signed_tbs);
    return ret;
}

result sec_signed_wsa_verification(struct sec_db* sdb,
                string* wsa,
                
                result_array *results,
                string* wsa_data,
                ssp_array* ssp_array,
                time64_with_standard_deviation* generation_time,
                time64 *expiry_time,
                three_d_location* location,
                struct time32_array *last_crl_time,
                struct time32_array *next_crl_time,
                certificate* certificate){
    result ret = SUCCESS;
    struct certificate_chain chain;
    struct certificate_chain tmp_chain;
    struct cme_permissions_array cme_permissions;
    struct geographic_region_array regions;
    struct verified_array verified;
    struct dot2_service_info_array ser_info_array;
    sec_data sec_data;
    string permission_indices;
    time64 g_time = 0;
    time64 e_time = 0;
    int len = 0;
    int i = 0;
    int j = 0;
    int k = 0;

    INIT(chain);
    INIT(tmp_chain);
    INIT(cme_permissions);
    INIT(regions);
    INIT(verified);
    INIT(sec_data);
    INIT(permission_indices);
    INIT(ser_info_array);

    if(string_2_sec_data(wsa, &sec_data)){
        wave_error_printf("sec_data解码失败");
        ret = FAILURE;
        goto end;
    }
    len = sec_data.u.signed_wsa.unsigned_wsa.permission_indices.len;

    if(!results){
        wave_error_printf("result array指针为空，没有返回值可以填写");
        ret = FAILURE;
        goto end;
    }
    if(sec_data.protocol_version != 2 || sec_data.type != SIGNED_WSA || sec_data.u.signed_wsa.signer.type != CERTIFICATE_CHAIN
                || sec_data.u.signed_wsa.unsigned_wsa.generation_time.time > sec_data.u.signed_wsa.unsigned_wsa.expire_time){
        results->len = len;
        if(results->result != NULL){
            wave_error_printf("result array中的buf不为空，存在野指针");
            ret = FAILURE;
            goto end;
        }
        results->result = malloc(sizeof(result)*len);
        if(!results->result){
            wave_error_printf("内存分配失败");
            ret = FAILURE;
            goto end;
        }
        for(i = 0; i < len; i++)
            results->result[i] = INVALID_INPUT;
    }

    //这个wsa_data是不是这个值，后面再讨论以下
    if(wsa_data != NULL){
        wsa_data->len = sec_data.u.signed_wsa.unsigned_wsa.data.len;
        if(wsa_data->buf != NULL){
            wave_error_printf("wsa data中的buf不为空，存在野指针");
            ret = FAILURE;
            goto end;
        }
        wsa_data->buf = malloc(sizeof(u8)*wsa_data->len);
        if(!wsa_data->buf){
            wave_error_printf("分配内存失败");
            ret = FAILURE;
            goto end;
        }
        memcpy(wsa_data->buf, sec_data.u.signed_wsa.unsigned_wsa.data.buf, wsa_data->len*sizeof(u8));
    }
    
    if(generation_time != NULL){
        generation_time->time = sec_data.u.signed_wsa.unsigned_wsa.generation_time.time;
        generation_time->long_std_dev = sec_data.u.signed_wsa.unsigned_wsa.generation_time.long_std_dev;
    }
    if(expiry_time != NULL)
        *expiry_time = sec_data.u.signed_wsa.unsigned_wsa.expire_time;
    g_time = sec_data.u.signed_wsa.unsigned_wsa.generation_time.time;
    e_time = sec_data.u.signed_wsa.unsigned_wsa.expire_time;
    if(location != NULL){
        location->latitude = sec_data.u.signed_wsa.unsigned_wsa.generation_location.latitude;
        location->longitude = sec_data.u.signed_wsa.unsigned_wsa.generation_location.longitude;
        location->elevation[0] = sec_data.u.signed_wsa.unsigned_wsa.generation_location.elevation[0];
        location->elevation[1] = sec_data.u.signed_wsa.unsigned_wsa.generation_location.elevation[1];
    }

    //extract the permission_indices
    permission_indices.len = sec_data.u.signed_wsa.unsigned_wsa.permission_indices.len;
    permission_indices.buf = malloc(sizeof(u8)*permission_indices.len);
    if(!permission_indices.buf){
        wave_error_printf("分配内存失败");
        ret = FAILURE;
        goto end;
    }
    memcpy(permission_indices.buf, sec_data.u.signed_wsa.unsigned_wsa.permission_indices.buf, permission_indices.len);

    
    for(i = 0; i < len; ++i){
        if(permission_indices.buf[i] == 0)
            results->result[i] == UNSECURED;
        else
            results->result[i] == UNDEFINED;
    }

    //提取出signed_wsa中的certificates.
    tmp_chain.len = sec_data.u.signed_wsa.signer.u.certificates.len;
    tmp_chain.certs = malloc(sizeof(certificate)*tmp_chain.len);
    if(!tmp_chain.certs){
        wave_error_printf("分配内存失败");
        ret = FAILURE;
        goto end;
    }
    for(i = 0; i < tmp_chain.len; i++)
        if(certificate_cpy(&tmp_chain.certs[i], &sec_data.u.signed_wsa.signer.u.certificates.buf[i])){
            wave_error_printf("证书copy失败");
            ret = FAILURE;
            goto end;
        }
    ret = cme_construct_certificate_chain(sdb, ID_CERTIFICATE, NULL, &tmp_chain, false, 8, &chain, &cme_permissions, &regions,
            last_crl_time, next_crl_time, &verified);

    ret = pssme_outoforder(sdb, g_time, &chain.certs[0]);
    if(ret == NOT_MOST_RECENT_WSA)
        goto end;

    ret = sec_check_certificate_chain_consistency(sdb, &chain, &cme_permissions, &regions);
    if(ret != SUCCESS)
        goto end;

    if(g_time / US_TO_S < chain.certs[0].unsigned_certificate.flags_content.start_validity)
        ret = FUTURE_CERTIFICATE_AT_GENERATION_TIME;
    if(g_time / US_TO_S > chain.certs[0].unsigned_certificate.expiration)
       ret = EXPIER_CERTIFICATE_AT_GENERATION_TIME;
    if(e_time / US_TO_S < chain.certs[0].unsigned_certificate.flags_content.start_validity)
        ret = EXPIRY_DATE_TOO_EARLY;
    if(e_time / US_TO_S > chain.certs[0].unsigned_certificate.expiration)
        ret = EXPIRY_DATE_TOO_LATE;

    //判断generation latitude和generation latitude是否在geoScopes[0]范围内

    if(chain.certs[0].unsigned_certificate.holder_type != WSA)
        ret = UNSUPPORTED_SIGNER_TYPE;
    if(ret != SUCCESS)
        goto end;

    //extract serviceinfo
    if(extract_service_info(wsa_data, &ser_info_array)){
        wave_error_printf("service info解析失败");
        goto end;
    }
    if(ser_info_array.len != permission_indices.len){
        ret = INVALID_INPUT;
        goto end;
    }
    for(i = 0; i < permission_indices.len; i++){
        if(permission_indices.buf[i] == 0){
            results->result[i] = UNSECURED;
            continue;
        }
        j = permission_indices.buf[i];
        switch(cme_permissions.cme_permissions[0].type){
            case PSID_PRIORITY:
                if(cme_permissions.cme_permissions[0].u.psid_priority_array.buf[j-1].psid != ser_info_array.service_infos[i].psid){
                    ret = INCONSISITENT_PERMISSIONS;
                    goto end;
                }
                if(cme_permissions.cme_permissions[0].u.psid_priority_array.buf[j-1].max_priority <= ser_info_array.service_infos[i].priority){
                    ret = UNAUTHORIZED_PSID_AND_PRIORITY_IN_WSA;
                    goto end;
                }
                ssp_array->ssps[i].buf = NULL;
                ssp_array->ssps[i].len = 0;
            case PSID_PRIORITY_SSP:
                if(cme_permissions.cme_permissions[0].u.psid_priority_ssp_array.buf[j-1].psid != ser_info_array.service_infos[i].psid){
                    ret = INCONSISITENT_PERMISSIONS;
                    goto end;
                }
                if(cme_permissions.cme_permissions[0].u.psid_priority_ssp_array.buf[j-1].max_priority <= ser_info_array.service_infos[i].priority){
                    ret = UNAUTHORIZED_PSID_AND_PRIORITY_IN_WSA;
                    goto end;
                }
                if(ssp_array != NULL){
                    ssp_array->len = permission_indices.len;
                    ssp_array->ssps = malloc(sizeof(string)*ssp_array->len);
                    if(!ssp_array->ssps){
                        wave_error_printf("内存分配失败");
                        ret = FAILURE;
                        goto end;
                    }
                    if(cme_permissions.cme_permissions[0].u.psid_priority_ssp_array.buf[j-1].service_specific_permissions.buf != NULL){
                        ssp_array->ssps[i].len = cme_permissions.cme_permissions[0].u.psid_priority_ssp_array.buf[j-1].service_specific_permissions.len;
                        ssp_array->ssps[i].buf = malloc(sizeof(u8)*ssp_array->ssps[i].len);
                        if(!ssp_array->ssps[i].buf){
                            wave_error_printf("分配内存失败!");
                            ret = FAILURE;
                            goto end;
                        }
                        memcpy(ssp_array->ssps[i].buf, cme_permissions.cme_permissions[0].u.psid_priority_ssp_array.buf[j-1].service_specific_permissions.buf,
                                ssp_array->ssps[i].len);
                    }
                    else{
                        ssp_array->ssps[i].buf = NULL;
                        ssp_array->ssps[i].len = 0;
                    }
                }
                break;
            default:
                wave_error_printf("错误的permission type!");
                ret = FAILURE;
                goto end;
        }
    }

    //verify the certificate chain and signature

end:
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
