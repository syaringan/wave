/*************************************************************************
    > File Name: sec.c
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2015年10月15日 星期四 17时12分57秒
 ************************************************************************/

#include "sec.h"
#include "pssme/pssme.h"
#include "data/data.h"
#include "cme/cme.h"
#include <time.h>
#include <math.h>
#include "../crypto/crypto.h"
#include "./utils/normal_distribution.h"
#define INIT(m) memset(&m,0,sizeof(m))
#define LOG_STD_DEV_BASE 1.134666

#define  certificate_request_permissions_max_length 255//配置变量，配置证书申请最大的长度
extern struct region_type_array certificate_request_support_region_types;//配置变量，表示支持的类型
#define certificate_request_rectangle_max_length 100
#define certificate_request_polygonal_max_length 100

static inline unsigned char ext_length(char *eid){
    return *((unsigned char *)eid + 1);
}

void ssp_array_free(struct ssp_array* ptr){
    if(ptr == NULL)
        return ;
    free(ptr->ssps);
    ptr->ssps = NULL;
    ptr->len = 0;
}

void result_array_free(struct result_array* ptr){
    if(ptr == NULL)
        return;
    free(ptr->result);
    ptr->len = 0;
    ptr->result = NULL;
}

void dot2_service_info_array_free(struct dot2_service_info_array *ptr){
    if(ptr == NULL)
        return;
    free(ptr->service_infos);
    ptr->len = 0;
    ptr->service_infos = NULL;
}

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
                break;
            case EID_CHANINFO:
                channel_info_index ++;
				if(channel_info_index > 6){
					return -1;
				}
                ch_info[channel_info_index].channel = eid_pos;
                current_shift += 6;
				if(channel_info_index)
                break;
            case EID_WRA:         
                if(wra_index == 255)
                    wra_index = 0;
                routing_adv->wra = (char *)eid_pos;
                current_shift += 52;
				if(wra_index)
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
        ser_infos->service_infos[i].psid = psidn2h(tmp, psid_len);

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
            switch(cert->unsigned_certificate.version_and_type.verification_key.algorithm){
                    case ECDSA_NISTP224_WITH_SHA224:
                       if( crypto_HASH_224(message,hashed) ){
                            goto fail;
                       }  
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       if( crypto_HASH_256(message,hashed))
                           goto fail;
                       break;
                    case ECIES_NISTP256:
                       wave_error_printf("这个是加密算法，怎么出现在了这个签名中");
                       goto fail;
                       break;
            } 
            break;
        case 3:
             switch(cert->unsigned_certificate.u.no_root_ca.signature_alg){
                    case ECDSA_NISTP224_WITH_SHA224:
                       if( crypto_HASH_224(message,hashed) ){
                            goto fail;
                       }  
                       break;
                    case ECDSA_NISTP256_WITH_SHA256:
                       if( crypto_HASH_256(message,hashed))
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

static int elliptic_curve_point_2_uncompressed(pk_algorithm algorithm,elliptic_curve_point* point,string *x,string *y){
    if(point->type == X_COORDINATE_ONLY){
        wave_error_printf("不应该有这个直 %s %d",__FILE__,__LINE__);
        return -1; 
    }
    int res =0;
    string compress;
    
    INIT(compress);

    if(point->type == UNCOMPRESSED){
        x->len = point->x.len;
        y->len = point->u.y.len;
        x->buf = (u8*)malloc(x->len);
        y->buf = (u8*)malloc(y->len);
        if(x->buf == NULL || y->buf == NULL){
            res = -1;
            goto end;
        }
        memcpy(x->buf,point->x.buf,x->len);
        memcpy(y->buf,point->u.y.buf,y->len);
        goto end;
    }
    compress.len = point->x.len;
    compress.buf = (u8*)malloc(compress.len);
    if(compress.buf == NULL){
        wave_malloc_error();
        res = -1;
        goto end;
    }
    memcpy(compress.buf,point->x.buf,compress.len);

    if(algorithm == ECDSA_NISTP256_WITH_SHA256){
        if(crypto_ECDSA_256_compress_key_2_uncompress(&compress,point->type,x,y)){
            res = -1;
            goto end;        
        }
    }
    else if(algorithm == ECDSA_NISTP224_WITH_SHA224){
        if(crypto_ECDSA_224_compress_key_2_uncompress(&compress,point->type,x,y)){
            res = -1;
            goto end;        
        }
    }
    else if(algorithm == ECIES_NISTP256){
        if(crypto_ECIES_compress_key_2_uncompress(&compress,point->type,x,y)){
            res = -1;
            goto end;
        }
    }
    else{
        wave_error_printf("不会出现这个指 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    goto end;
end:
    if(res != 0){
        string_free(x);
        string_free(y);
    }
    string_free(&compress);
    return res;
}
int elliptic_curve_point_2_compressed(pk_algorithm algorithm,elliptic_curve_point* point,string* compress,enum ecc_public_keytype *type){
    if(point->type == X_COORDINATE_ONLY){
        wave_error_printf("不应该有这个直 %s %d",__FILE__,__LINE__);
        return -1; 
    }
    int res = 0;
    string x,y;

    INIT(x);
    INIT(y);
    
    if(point->type == UNCOMPRESSED){
        x.len = point->x.len;
        y.len = point->u.y.len;
        if( (x.buf = (u8*)malloc(x.len)) == NULL || (y.buf = (u8*)malloc(y.len)) == NULL ){
            wave_malloc_error();
            res = -1;
            goto end;
        }
        memcpy(x.buf,point->x.buf,x.len);
        memcpy(y.buf,point->u.y.buf,y.len);

        if(algorithm == ECDSA_NISTP224_WITH_SHA224){    
            if( crypto_ECDSA_224_uncompress_key_2_compress_key(&x,&y,compress,type)){
                res = -1;
                goto end;
            } 
        }
        else if(algorithm == ECDSA_NISTP256_WITH_SHA256){ 
            if( crypto_ECDSA_256_uncompress_key_2_compress_key(&x,&y,compress,type)){
                res = -1;
                goto end;
            } 
        }
        else if(algorithm == ECIES_NISTP256){
            if( crypto_ECIES_uncompress_key_2_compress_key(&x,&y,compress,type)){
                res = -1;
                goto end;
            }
        }
        else{
            wave_error_printf("出现了不可能出现的直 %s %d",__FILE__,__LINE__);
            res = -1;
            goto end;
        }
    }
    else{
        if(type != NULL){
            *type = point->type;
        }
        compress->len = point->x.len;
        compress->buf = (u8*)malloc(compress->len);
        if(compress->buf == NULL){
            wave_malloc_error();
            res = -1;
            goto end;
        }
        memcpy(compress->buf,point->x.buf,compress->len);
    }
    goto end;
end:
    string_free(&x);
    string_free(&y);
    return res;
}
static int certificate_verification_point_compress(certificate* cert,bool compressed){
    pk_algorithm algorithm;
    elliptic_curve_point *point;
    string compress;
    string x,y;
    int res = 0;

    INIT(compress);
    INIT(x);
    INIT(y);

    if(cert->version_and_type == 3){
        algorithm = cert->unsigned_certificate.u.no_root_ca.signature_alg;
        point = &cert->u.reconstruction_value;
    }
    else if(cert->version_and_type == 2){
        algorithm = cert->unsigned_certificate.version_and_type.verification_key.algorithm;
        if(algorithm != ECDSA_NISTP224_WITH_SHA224 && algorithm != ECDSA_NISTP256_WITH_SHA256){
            wave_error_printf("这里之支持签名点的压缩  %s %d",__FILE__,__LINE__);
            return -1; 
        }

        point = &cert->unsigned_certificate.version_and_type.verification_key.u.public_key;
    }
    if(compressed == true){
        if(point->type == COMPRESSED_LSB_Y_0 || point->type == COMPRESSED_LSB_Y_1)
            goto end;

        if( elliptic_curve_point_2_compressed(algorithm,point,&compress,&point->type)){
            res = -1;
            goto end;
        }
        point->x.len = compress.len;
        point->x.buf = (u8*)realloc(point->x.buf,compress.len);
        if(point->x.buf == NULL){
            wave_malloc_error();
            wave_error_printf("这个错误是不是会修改证书，引起潜在的问题，但是数据库的证书都是复制出来的，注意chekc %s %d",__FILE__,__LINE__);
           res = -1;
            goto end;
        }
        memcpy(point->x.buf,compress.buf,compress.len);

        if(point->u.y.buf != NULL){
            free(point->u.y.buf);
            point->u.y.buf = NULL;
            point->u.y.len = 0;
        }
    }
    else{
        if(point->type == UNCOMPRESSED)
            goto end;
        if( elliptic_curve_point_2_uncompressed(algorithm,point,&x,&y)){
            res = -1;
            goto end;
        }
        
        point->x.len = x.len;
        point->u.y.len = y.len;
        point->x.buf = (u8*)realloc(point->x.buf,x.len);
        point->u.y.buf = (u8*)realloc(point->u.y.buf,y.len);
        if(point->x.buf == NULL || point->u.y.buf == NULL){
            wave_malloc_error();
            res = -1;
            goto end;
        }

        memcpy(point->x.buf,x.buf,x.len);
        memcpy(point->u.y.buf,y.buf,y.len);
    }
    goto end;
end:
    string_free(&compress);
    string_free(&x);
    string_free(&y);
    return res;
}
static int signature_generation(signature *sig,enum pk_algorithm algorithm,enum sign_with_fast_verification fs_type,string *mess,string* prikey){
    string hash,r,r_x,r_y,s,comp;
    int res = 0;

    INIT(hash);
    INIT(r);
    INIT(r_x);
    INIT(r_y);
    INIT(s);
    INIT(comp);

    if(algorithm != ECDSA_NISTP224_WITH_SHA224 && algorithm != ECDSA_NISTP256_WITH_SHA256){
        wave_error_printf("我们不支持其他的签名方式  %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    if(algorithm == ECDSA_NISTP224_WITH_SHA224){
        if(fs_type == NO){
            if( crypto_HASH_224(mess,&hash) ||
                    crypto_ECDSA_224_sign_message(prikey,mess,&r,&s)){
                res = -1;
                goto end;
            }
            sig->u.ecdsa_signature.r.type = X_COORDINATE_ONLY;
            sig->u.ecdsa_signature.r.x.len = r.len;
            sig->u.ecdsa_signature.r.x.buf =(u8*)malloc(r.len);
            if(sig->u.ecdsa_signature.r.x.buf == NULL){
                wave_malloc_error();
                res = -1;
                goto end;
            }
            memcpy(sig->u.ecdsa_signature.r.x.buf,r.buf,r.len);
        }
        else{
            if(crypto_HASH_224(mess,&hash) || 
                   crypto_ECDSA_224_FAST_sign_message(prikey,mess,&r_x,&r_y,&s)){
                res = -1;
                goto end;
            }
            if(fs_type == YES_UNCOMPRESSED){
                sig->u.ecdsa_signature.r.type = UNCOMPRESSED;
                sig->u.ecdsa_signature.r.x.len = r_x.len;
                sig->u.ecdsa_signature.r.x.buf =(u8*)malloc(r_x.len);
                if(sig->u.ecdsa_signature.r.x.buf == NULL){
                    wave_malloc_error();
                    res = -1;
                    goto end;
                }
                memcpy(sig->u.ecdsa_signature.r.x.buf,r_x.buf,r_x.len);
                
                sig->u.ecdsa_signature.r.u.y.len = r_y.len;
                sig->u.ecdsa_signature.r.u.y.buf =(u8*)malloc(r_y.len);
                if(sig->u.ecdsa_signature.r.u.y.buf == NULL){
                    wave_malloc_error();
                    res = -1;
                    goto end;
                }
                memcpy(sig->u.ecdsa_signature.r.u.y.buf,r_y.buf,r_y.len);
            }
            else if(fs_type == YES_COMPRESSED){
                 if(crypto_ECDSA_224_uncompress_key_2_compress_key(&r_x,&r_y,&comp,&sig->u.ecdsa_signature.r.type)){
                    res = -1;
                    goto end;
                 }
                 sig->u.ecdsa_signature.r.x.len = comp.len;
                 sig->u.ecdsa_signature.r.x.buf = (u8*)malloc(comp.len);
                 if(sig->u.ecdsa_signature.r.x.buf == NULL){
                    wave_malloc_error();
                    res = -1;
                    goto end;
                 }
                 memcpy(sig->u.ecdsa_signature.r.x.buf,comp.buf,comp.len);
            }
            else{
                wave_error_printf("有问题哦 %s %d",__FILE__,__LINE__);
                res = -1;
                goto end;
            }
        }
    }
    else if(algorithm == ECDSA_NISTP256_WITH_SHA256){
        if(fs_type == NO){
            if( crypto_HASH_256(mess,&hash) ||
                    crypto_ECDSA_256_sign_message(prikey,mess,&r,&s)){
                res = -1;
                goto end;
            }
            sig->u.ecdsa_signature.r.type = X_COORDINATE_ONLY;
            sig->u.ecdsa_signature.r.x.len = r.len;
            sig->u.ecdsa_signature.r.x.buf =(u8*)malloc(r.len);
            if(sig->u.ecdsa_signature.r.x.buf == NULL){
                wave_malloc_error();
                res = -1;
                goto end;
            }
            memcpy(sig->u.ecdsa_signature.r.x.buf,r.buf,r.len);
        }
        else{
            if(crypto_HASH_256(mess,&hash) || 
                   crypto_ECDSA_256_FAST_sign_message(prikey,mess,&r_x,&r_y,&s)){
                res = -1;
                goto end;
            }
            if(fs_type == YES_UNCOMPRESSED){
                sig->u.ecdsa_signature.r.type = UNCOMPRESSED;
                sig->u.ecdsa_signature.r.x.len = r_x.len;
                sig->u.ecdsa_signature.r.x.buf =(u8*)malloc(r_x.len);
                if(sig->u.ecdsa_signature.r.x.buf == NULL){
                    wave_malloc_error();
                    res = -1;
                    goto end;
                }
                memcpy(sig->u.ecdsa_signature.r.x.buf,r_x.buf,r_x.len);
                
                sig->u.ecdsa_signature.r.u.y.len = r_y.len;
                sig->u.ecdsa_signature.r.u.y.buf =(u8*)malloc(r_y.len);
                if(sig->u.ecdsa_signature.r.u.y.buf == NULL){
                    wave_malloc_error();
                    res = -1;
                    goto end;
                }
                memcpy(sig->u.ecdsa_signature.r.u.y.buf,r_y.buf,r_y.len);
            }
            else if(fs_type == YES_COMPRESSED){
                 if(crypto_ECDSA_256_uncompress_key_2_compress_key(&r_x,&r_y,&comp,&sig->u.ecdsa_signature.r.type)){
                    res = -1;
                    goto end;
                 }
                 sig->u.ecdsa_signature.r.x.len = comp.len;
                 sig->u.ecdsa_signature.r.x.buf = (u8*)malloc(comp.len);
                 if(sig->u.ecdsa_signature.r.x.buf == NULL){
                    wave_malloc_error();
                    res = -1;
                    goto end;
                 }
                 memcpy(sig->u.ecdsa_signature.r.x.buf,comp.buf,comp.len);
            }
            else{
                wave_error_printf("有问题哦 %s %d",__FILE__,__LINE__);
                res = -1;
                goto end;
            }
        }
    }
    else{
        wave_error_printf("参数有问题 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }

    sig->u.ecdsa_signature.s.len = s.len;
    sig->u.ecdsa_signature.s.buf = (u8*)malloc(s.len);
    if(sig->u.ecdsa_signature.s.buf == NULL){
        wave_malloc_error();
        res = -1;
        goto end;
    }
    memcpy(sig->u.ecdsa_signature.s.buf,s.buf,s.len);
    goto end;
end:
    string_free(&hash);
    string_free(&r);
    string_free(&r_x);
    string_free(&r_y);
    string_free(&s);
    string_free(&comp);
    return res;
}
//cert_chani_len == 257的时候代表MAX
result sec_signed_data(struct sec_db* sdb,cmh cmh,content_type type,string* data,string* exter_data,psid psid,
                    string* ssp,bool set_generation_time, time64_with_standard_deviation* generation_time,
                    bool set_generation_location,three_d_location* location,bool set_expiry_time,time64 expiry_time,
                    enum signed_data_signer_type signer_type,s32 cert_chain_len,u32 cert_chain_max_len,enum sign_with_fast_verification fs_type,
                    bool compressed,
                    
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
    string encoded_tbs,privatekey;
    pk_algorithm algorithm = PK_ALGOTITHM_NOT_SET;//这里让他等于一个不可能的指
    int i;

    res = SUCCESS;
    INIT(cert);
    INIT(cert_chain);
    INIT(construct_cert_chain);
    INIT(regions);
    INIT(permissions);
    INIT(sec_data);
    INIT(encoded_tbs);
    INIT(privatekey);
    
    s_data = &sec_data.u.signed_data;
    tbs_encode = &s_data->unsigned_data;
    if( res = find_cert_prikey_by_cmh(sdb,cmh,&cert,&privatekey) ){
        goto end;
    }
    cert_chain.certs = &cert;
    cert_chain.len = 1;
    if(  cme_construct_certificate_chain(sdb,ID_CERTIFICATE,NULL,&cert_chain,true,cert_chain_max_len,
                &construct_cert_chain,&permissions,&regions,NULL,NULL,NULL)  != SUCCESS){
        res = NOT_FOUND;
        goto end;
    }
    if(certificate_get_start_time(&cert,&start_time) || 
            certificate_get_expired_time(sdb,&cert,&expired_time)){
        wave_error_printf("获取证书相关信息不对，这个证书没有这个信息");
        res = FAILURE;
        goto end;
    }
    if(generation_time->time/US_TO_S < start_time){
        wave_error_printf("生产时期早于了证书的开始有效时间 generetion_time:%us start_time:%us,now:%us",
                (time32)(generation_time->time/US_TO_S),start_time,time(NULL));
        res = CERTIFICATE_NOT_YET_VALID;
        goto end;
    }
    if(generation_time->time/US_TO_S > expired_time){
         wave_error_printf("生产日期晚育了证书的结束有效时间 generation_time:%us expired_time:%us,now:%us",
                 (time32)(generation_time->time/US_TO_S),expired_time,time(NULL));
         res = CERTIFICATE_EXPIRED;
         goto end;
    }
    if(set_expiry_time){
        if(expiry_time/US_TO_S < start_time){
            wave_error_printf("过期时间早育了证书的开始有效时间 expiry_time:%us start_time:%us",
                    expiry_time/US_TO_S,start_time);
            res = EXPIRY_TIME_BEFORE_CERTIFICATE_VALIDITY_PERIOD;
            goto end;
        }
        if(expiry_time/US_TO_S > expired_time){
            wave_error_printf("过期时间晚育了证书的结束的有效时间 expiry_time:%us expired_time:%us",
                    (time32)(expiry_time/US_TO_S),expired_time);
            res = EXPIRY_TIME_AFTER_CERTIFICATE_VALIDITY_PERIOD;
            goto end;
        }
    }
    if( three_d_location_in_region(location,regions.regions) == false){
        wave_error_printf("生产地点不在证书范围内");
        res = OUTSIDE_CERTIFICATE_VALIDITY_REGION;
        goto end;
    }
    if( cme_permissions_contain_psid_with_ssp(permissions.cme_permissions,psid,ssp) ==false){
        wave_error_printf("证书权限和用户要求的不一致");
        res = INCONSISTENT_PERMISSIONS_IN_CERTIFICATE;
        goto end;
    }

    if(signer_type == CERTIFICATE_CHAIN && 
            (cert_chain_len > construct_cert_chain.len || -cert_chain_len > construct_cert_chain.len)){
        if(len_of_cert_chain != NULL)
            *len_of_cert_chain = construct_cert_chain.len;
        wave_error_printf("证书连请求长度请求不正确");
        res = INCORRECT_REQUSET_CERTIFICATE_CHAIN_LENGTH;
        goto end;
    } 

    switch(type){
        case SIGNED:
            tbs_encode->u.type_signed.psid = psid;
            
            tbs_encode->u.type_signed.data.len = data->len;
            tbs_encode->u.type_signed.data.buf = 
                    (u8*)malloc(data->len);
            if(tbs_encode->u.type_signed.data.buf == NULL){
                wave_malloc_error();
                res = -1;
                goto end;
            }
            memcpy(tbs_encode->u.type_signed.data.buf,data->buf,data->len);
            break;
        case SIGNED_PARTIAL_PAYLOAD:
            tbs_encode->u.type_signed_partical.psid = psid;

            tbs_encode->u.type_signed_partical.data.len = data->len;
            tbs_encode->u.type_signed_partical.data.buf = 
                    (u8*)malloc(data->len);
            if(tbs_encode->u.type_signed_partical.data.buf == NULL){
                wave_malloc_error();
                res = -1;
                goto end;
            }
            memcpy(tbs_encode->u.type_signed_partical.data.buf,data->buf,data->len);

            if(exter_data != NULL){
                tbs_encode->u.type_signed_partical.ext_data.len = exter_data->len;
                tbs_encode->u.type_signed_partical.ext_data.buf = 
                    (u8*)malloc(exter_data->len);
                if(tbs_encode->u.type_signed_partical.ext_data.buf == NULL){
                    wave_malloc_error();
                    res = -1;
                    goto end;
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
                    res = -1;
                    goto end;
                }
                memcpy(tbs_encode->u.type_signed_external.ext_data.buf,exter_data->buf,exter_data->len);
            }
            else{
                wave_error_printf("模式为external_payload,但是你的exter_data为null");
                res = -1;
                goto end;
            }
            break;
        default:
            wave_error_printf("这个指的话，是没有psid的。。怎么版，我只有返回错误,要不我这里暂时不支持这种");
            res = FAILURE;
            goto end;
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
    if( tobesigned_data_2_string(tbs_encode,&encoded_tbs,type) ){
        wave_error_printf("编码失败");
        res = -1;
        goto end;
    }
    
    switch(cert.version_and_type){
        case 2:
            algorithm = cert.unsigned_certificate.version_and_type.verification_key.algorithm;
            break;
        case 3:
            algorithm = cert.unsigned_certificate.u.no_root_ca.signature_alg;
            break;
        default:
            wave_error_printf("出现了不可能出现的指 %s %d ",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
    }
    if(algorithm != ECDSA_NISTP224_WITH_SHA224 && algorithm != ECDSA_NISTP256_WITH_SHA256){
        wave_error_printf("这里的协议类型都不等于我们要求的这里有问题,我们这里暂时不支持其他的签名算法");
        res = -1;
        goto end;
    }
    if( signature_generation(&s_data->signature,algorithm,fs_type,&encoded_tbs,&privatekey)){
        res = -1;
        goto end;        
    }
    
    if(signer_type == SIGNED_DATA_CERTIFICATE_DIGEST){
        if(algorithm == ECDSA_NISTP256_WITH_SHA256)
            s_data->signer.type = CERTIFICATE_DIGEST_WITH_ECDSAP256;
        else if(algorithm == ECDSA_NISTP224_WITH_SHA224)
           s_data->signer.type = CERTIFICATE_DIGEST_WITH_ECDSAP224; 
        if( certificate_2_hashedid8(&cert,&s_data->signer.u.digest)){
            res = -1;
            goto end;
        }
        
        //这里是1嘛？？协议没说，我按照自己的想法加的
        if(len_of_cert_chain != NULL)
                *len_of_cert_chain = 1;
    }
    else if(signer_type == SIGNED_DATA_CERTIFICATE){
        s_data->signer.type = CERTIFICATE;
        certificate_cpy(&s_data->signer.u.certificate,&cert);
        if(certificate_verification_point_compress(&s_data->signer.u.certificate,compressed)){
            res = -1;
            goto end;
        }
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
                res = -1;
                goto end;
            }
            s_data->signer.u.certificates.len = construct_cert_chain.len;
            for(i=0;i<construct_cert_chain.len;i++){
                certificate_cpy(s_data->signer.u.certificates.buf+i,construct_cert_chain.certs+i);
                if(certificate_verification_point_compress(s_data->signer.u.certificates.buf+i,compressed)){
                    res = -1;
                    goto end;
                }
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
                res = -1;
                goto end;
            } 
            for(i=0;i<s_data->signer.u.certificates.len;i++){
                certificate_cpy(s_data->signer.u.certificates.buf+i,construct_cert_chain.certs+i);
                if(certificate_verification_point_compress(s_data->signer.u.certificates.buf+i,compressed)){
                    res = -1;
                    goto end;
                }
            }            
        }
        else if(cert_chain_len <0){
            if(construct_cert_chain.len - 1 < -cert_chain_len){
                wave_error_printf("要求删掉的链表长度长于生成的链表长度 %s %d\n",__FILE__,__LINE__);
                res = -1;
                goto end;
            }
            s_data->signer.u.certificates.len = construct_cert_chain.len + cert_chain_len;
            s_data->signer.u.certificates.buf = (certificate*)malloc(sizeof(certificate) *
                   s_data->signer.u.certificates.len);
            if(s_data->signer.u.certificates.buf == NULL){
                wave_malloc_error();
                res = -1;
                goto end;
            }
            certificate_cpy(s_data->signer.u.certificates.buf,construct_cert_chain.certs);
            //这里我不知道我的理解对不，是负数，就删除前面几个，但是第一个不删除;
            for(i=0;i<-cert_chain_len -1;i++){
                certificate_cpy(s_data->signer.u.certificates.buf+i,construct_cert_chain.certs+i-cert_chain_len+1);
                if(certificate_verification_point_compress(s_data->signer.u.certificates.buf+i,compressed)){
                    res = -1;
                    goto end;
                }
            }
           
        }
        else{
            wave_error_printf("证书连要求长度为0，这个我不知道怎么半，我直接返回错误");
            res = -1;
            goto end;
        }
        if(len_of_cert_chain != NULL)
                *len_of_cert_chain = s_data->signer.u.certificates.len;
    }
    else{
        wave_error_printf("这个signer_type出现了不正确的指");
        res = -1;
        goto end;
    }
     
   
    sec_data.type = type;
    sec_data.protocol_version = CURRETN_VERSION; 
    if( sec_data_2_string(&sec_data,signed_data)){
        res = -1;
        goto end;
    }
    /*
    struct sec_data mmm;
    int jj;
    INIT(mmm);
    for(jj=0;jj<signed_data->len;jj++){
            printf("%02x ",signed_data->buf[jj]);
            if((jj+1)%10 == 0)
                printf("\n");
        }
    printf("\n");
    if(string_2_sec_data(signed_data,&mmm)){
        printf("string 2 sec data shibai %s %d\n",__FILE__,__LINE__);
    }
    else{
        for(jj=0;jj<signed_data->len;jj++){
            printf("%02x ",signed_data->buf[jj]);
        }
        printf("\n");
    }
    */
    res = SUCCESS;
    goto end;
    
end:
    certificate_free(&cert);
    certificate_chain_free(&construct_cert_chain);
    geographic_region_array_free(&regions);
    cme_permissions_array_free(&permissions);
    sec_data_free(&sec_data);
    string_free(&encoded_tbs);
    string_free(&privatekey);
    return res;
}
static inline int certificate_chain_add_cert(struct certificate_chain* certs,certificate* cert){
            DEBUG_MARK;
    printf("certs->len %d certs->certs:%p %s %d\n",certs->len,certs->certs,__FILE__,__LINE__);
    if(certs->len == 0){
        certs->certs = (struct certificate*)malloc(sizeof(struct certificate));
        if(certs->certs == NULL){
            wave_malloc_error();
            return -1;
        }
    }
    else{
        certs->certs = (struct certificate*)realloc(certs->certs, sizeof(struct certificate)*certs->len+1);
        if(certs->certs == NULL){
            wave_malloc_error();
            return -1;
        }
    }
    certs->len++;
            DEBUG_MARK;
    certificate_cpy(certs->certs+certs->len-1,cert);
            DEBUG_MARK;
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
    string ok,nonce;
    string x,y,ephe_x,ephe_y,compress_point;
    string encrypted_mess,tag;
    string plaintext,ciphertext;
    sec_data sdata;
    tobe_encrypted tbencrypted;
    recipient_info *rec_info; 
    elliptic_curve_point *point;
    time32 next_crl_time;
    time_t now;
    
    INIT(enc_certs);
    INIT(symm_key);
    INIT(cert_string);
    INIT(ok);
    INIT(nonce);
    INIT(sdata);
    INIT(x);
    INIT(y);
    INIT(ephe_x);
    INIT(ephe_y);
    INIT(encrypted_mess);
    INIT(tag);
    INIT(compress_point);
    INIT(plaintext);
    INIT(ciphertext);
    INIT(tbencrypted);
    
    sdata.type = ENCRYPTED;
    sdata.protocol_version = CURRETN_VERSION;
    failed_certs->len = 0;
    for(i=0;i<certs->len;i++){
        string_free(&cert_string);
        temp_cert = certs->certs+i;
        if( certificate_2_string(temp_cert,&cert_string)){
            res = FAILURE;
            goto end;
        }
        res = cme_certificate_info_request(sdb,ID_CERTIFICATE,&cert_string, 
                            NULL,NULL,NULL,NULL,&next_crl_time,NULL,NULL);
        if(res != FOUND){
            res = FAIL_ON_SOME_CERTIFICATES;
            if(certificate_chain_add_cert(failed_certs,temp_cert)){
                res = -1;
                goto end;
            }
        }
        else{
            time(&now);
            if(next_crl_time < now - overdue_crl_tolerance/US_TO_S){
                wave_printf(MSG_WARNING,"crl没有获得，crl_next_time:%d  now:%d  over:%lld\n",
                        next_crl_time,now,overdue_crl_tolerance/US_TO_S);
                res = FAIL_ON_SOME_CERTIFICATES;
                if(certificate_chain_add_cert(failed_certs,temp_cert)){
                    res = -1;
                    goto end;
                }
            }
            else{
                if((temp_cert->unsigned_certificate.cf & ENCRYPTION_KEY) == 0){
                    res = FAIL_ON_SOME_CERTIFICATES;
                    if(certificate_chain_add_cert(failed_certs,temp_cert)){
                        res = -1;
                        goto end;
                    }
                }
                else{
                    current_symm_alg = temp_cert->unsigned_certificate.flags_content.encryption_key.u.ecies_nistp256.supported_symm_alg;
                    if(current_symm_alg != AES_128_CCM){
                        wave_error_printf("我们目前支持的加密算法只有AES_128_CCM %s %d",__FILE__,__LINE__);
                        res = FAIL_ON_SOME_CERTIFICATES;
                        if(certificate_chain_add_cert(failed_certs,temp_cert)){
                            res = -1;
                            goto end;
                        }
                    }
                    else{
                        //这个地方我不知道我理解对没有，，请后来的人在核实一下，我是按照我的逻辑和想法猜测的
                        if( symm_alg != SYMM_ALGORITHM_NOT_SET && symm_alg != current_symm_alg){
                            res = FAIL_ON_SOME_CERTIFICATES;
                            if( certificate_chain_add_cert(failed_certs,temp_cert)){
                                res = -1;
                                goto end;
                            }
                        }
                        else{
                            symm_alg = current_symm_alg;
                            if(certificate_chain_add_cert(&enc_certs,temp_cert)){
                                res = -1;
                                goto end;
                            }
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
        res = -1;
        goto end;
    }
    sdata.u.encrypted_data.recipients.len = enc_certs.len;

    if(crypto_AES_128_CCM_Get_Key_and_Nonce(&ok,&nonce)){
        res = -1;
        goto end;
    }

            DEBUG_MARK;
    for(i=0;i<enc_certs.len;i++){
        rec_info = sdata.u.encrypted_data.recipients.buf+i;

            DEBUG_MARK;
        if(certificate_2_hashedid8(enc_certs.certs+i,&rec_info->cert_id)){
            res = -1;
            goto end;
        }

            DEBUG_MARK;
        point = &( (enc_certs.certs+i)->unsigned_certificate.flags_content.encryption_key.u.ecies_nistp256.public_key);
        if( elliptic_curve_point_2_uncompressed(ECIES_NISTP256,point,&x,&y)){
                res = -1;
                goto end;
        }

            DEBUG_MARK;
        if(crypto_ECIES_encrypto_message(&ok,&x,&y, &ephe_x,&ephe_y, &encrypted_mess,&tag)){
            res = -1;
            goto end;
        }
        
            DEBUG_MARK;
        if(compressed == true){
            DEBUG_MARK;
            if(crypto_ECIES_uncompress_key_2_compress_key(&ephe_x,&ephe_y,&compress_point,&rec_info->u.enc_key.v.type)){
                res = -1;
                goto end;
            }
            rec_info->u.enc_key.v.x.len = compress_point.len;
            rec_info->u.enc_key.v.x.buf = (u8*)malloc(compress_point.len);
            if(rec_info->u.enc_key.v.x.buf == NULL){
                res = -1;
                goto end;
            }
            memcpy(rec_info->u.enc_key.v.x.buf,compress_point.buf,compress_point.len);
        }
        else{
            DEBUG_MARK;
            rec_info->u.enc_key.v.x.len = ephe_x.len;
            rec_info->u.enc_key.v.u.y.len = ephe_y.len;

            rec_info->u.enc_key.v.x.buf = (u8*)malloc(ephe_x.len);
            rec_info->u.enc_key.v.u.y.buf = (u8*)malloc(ephe_y.len);

            if(rec_info->u.enc_key.v.x.buf == NULL ||
                    rec_info->u.enc_key.v.u.y.buf == NULL){
                wave_malloc_error();
                res = -1;
                goto end;
            }
            memcpy(rec_info->u.enc_key.v.x.buf,ephe_x.buf,ephe_x.len);
            memcpy(rec_info->u.enc_key.v.u.y.buf,ephe_y.buf,ephe_y.len);
        }
            DEBUG_MARK;
        rec_info->u.enc_key.c.len = encrypted_mess.len;
        rec_info->u.enc_key.c.buf = (u8*)malloc(rec_info->u.enc_key.c.len);
        if(rec_info->u.enc_key.c.buf == NULL){
            res = -1;
            wave_malloc_error();
            goto end;
        }
            DEBUG_MARK;
        memcpy(rec_info->u.enc_key.c.buf,encrypted_mess.buf,encrypted_mess.len);
        memcpy(rec_info->u.enc_key.t,tag.buf,tag.len);
        
        string_free(&x);
        string_free(&y);
        string_free(&ephe_x);
        string_free(&ephe_y);
        string_free(&encrypted_mess);
        string_free(&tag);
        string_free(&compress_point);
    }
    if(type == UNSECURED){
        tbencrypted.type = UNSECURED;
        tbencrypted.u.plain_text.len = data->len;
        tbencrypted.u.plain_text.buf = (u8*)malloc(data->len);
        if(tbencrypted.u.plain_text.buf == NULL){
            res = -1;
            goto end;
        }
            DEBUG_MARK;
        memcpy(tbencrypted.u.plain_text.buf,data->buf,data->len);
    }
    else if(type == SIGNED || type == SIGNED_PARTIAL_PAYLOAD || type == SIGNED_EXTERNAL_PAYLOAD){
        tbencrypted.type = type;
        if(  string_2_signed_data(data,&tbencrypted.u.signed_data,type) <=0 ){
            wave_error_printf("string_2_signed_data 失败 %s %d",__FILE__,__LINE__);
            res = -1;
            goto end;
        }
    }
    else{
        wave_error_printf("不知起其他的type  %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    
    if(tobe_encrypted_2_string(&tbencrypted,&plaintext)){
        wave_error_printf("tobe encrypted 编码失败  %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
            DEBUG_MARK;
    if(crypto_AES_128_CCM_encrypto_message(&plaintext,&ok,&nonce,&ciphertext)){
        res = -1;
        wave_error_printf("对成加密失败  %s %d",__FILE__,__LINE__);
        goto end;
    }
            DEBUG_MARK;
    memcpy(sdata.u.encrypted_data.u.ciphertext.nonce,nonce.buf,nonce.len);
            DEBUG_MARK;
    sdata.u.encrypted_data.u.ciphertext.ccm_ciphertext.len = ciphertext.len;
            DEBUG_MARK;
    sdata.u.encrypted_data.u.ciphertext.ccm_ciphertext.buf = (u8*)malloc(ciphertext.len);
            DEBUG_MARK;
    if(sdata.u.encrypted_data.u.ciphertext.ccm_ciphertext.buf == NULL){
        wave_malloc_error();
        res = -1;
        goto end;
    }
            DEBUG_MARK;
    memcpy(sdata.u.encrypted_data.u.ciphertext.ccm_ciphertext.buf,ciphertext.buf,ciphertext.len);

            DEBUG_MARK;
    if(encrypted_data != NULL){
        if(sec_data_2_string(&sdata,encrypted_data)){
            wave_error_printf("sec_data 编码失败了  %s %d",__FILE__,__LINE__);
            res = -1;
            goto end;
        }
       
    }
    res = SUCCESS;
    goto end;
end:
    string_free(&symm_key);
    certificate_chain_free(&enc_certs);
    string_free(&cert_string);
    string_free(&ok);
    string_free(&nonce);
    sec_data_free(&sdata);
    string_free(&x);
    string_free(&y);
    string_free(&ephe_x);
    string_free(&ephe_y);
    string_free(&encrypted_mess);
    string_free(&tag);
    string_free(&compress_point);
    string_free(&plaintext);
    string_free(&ciphertext);
    tobe_encrypted_free(&tbencrypted);
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

    
    if(  string_2_sec_data(recieve_data,&sdata) <= 0){
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
                    if(data != NULL){
                        data->len = s_data->unsigned_data.u.type_signed.data.len;
                        data->buf = (u8*)malloc(data->len);
                        if(data->buf == NULL){
                            wave_malloc_error();
                            res = FAILURE;
                            goto end;
                        }
                        memcpy(data->buf,s_data->unsigned_data.u.type_signed.data.buf,data->len);
                    }
                    break;
                case SIGNED_PARTIAL_PAYLOAD:
                    m_psid = s_data->unsigned_data.u.type_signed_partical.psid;
                    if(data != NULL){
                        data->len = s_data->unsigned_data.u.type_signed_partical.data.len;
                        data->buf = (u8*)malloc(data->len);
                        if(data->buf == NULL){
                            wave_malloc_error();
                            res = FAILURE;
                            goto end;
                        }
                        memcpy(data->buf,s_data->unsigned_data.u.type_signed_partical.data.buf,data->len);
                    }
                    break;
                case SIGNED_EXTERNAL_PAYLOAD:
                    m_psid = s_data->unsigned_data.u.type_signed_external.psid;
                    if(data != NULL){
                        data->len = s_data->unsigned_data.u.type_signed_external.ext_data.len;
                        data->buf = (u8*)malloc(data->len);
                        if(data->buf == NULL){
                            wave_malloc_error();
                            res = FAILURE;
                            goto end;
                        }
                        memcpy(data->buf,s_data->unsigned_data.u.type_signed_external.ext_data.buf,data->len);
                    }
                    break;
            }
            if(signed_data != NULL && signed_data->buf == NULL){
                if(signed_data_2_string(s_data,signed_data,type)){
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
                    certificate_2_string(signer->u.certificates.buf,&temp);
                }
                res = cme_certificate_info_request(sdb,ID_CERTIFICATE,&temp,NULL,&permissions,NULL,NULL,
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
                if(res != FOUND){
                    res = UNKNOWN_CERTIFICATE;
                    goto end;
                }
                if(send_cert != NULL){
                    if(signer->type == CERTIFICATE){
                        certificate_cpy(send_cert,&signer->u.certificate);
                    }
                    else{
                       // certificate_cpy(send_cert,&signer->u.certificates.buf+signer->u.certificates.len-1);
                        certificate_cpy(send_cert,&signer->u.certificates.buf);
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
                    ssp->buf = (u8*)malloc(ssp->len);
                    if( ssp->buf == NULL){
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

    result res = SUCCESS,res_temp;

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
    bool init_gen_loc = false;


    INIT(certs_chain);
    INIT(temp_certs_chain);
    INIT(permissions);
    INIT(geo_scopes);
    INIT(verifieds);
    INIT(s_data);
    INIT(expiry_time);
    INIT(gen_time);
    INIT(string);
    INIT(gen_loc);
    INIT(times);
    INIT(digest);

    if( string_2_signed_data(signed_data, &s_data,type) <=0 ){
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
                //goto next;
            }
            else{
                wave_printf(MSG_DEBUG,"generation_time 不相等  gen_time: %llu  generation_time:%llu",gen_time.time,generation_time->time);
                res = INVALID_INPUT;
                goto next;
            }

            if(gen_time.long_std_dev == generation_time->long_std_dev){
                res = SUCCESS;
               // goto next;
            }
            else{
                res = INVALID_INPUT;
                wave_printf(MSG_DEBUG,"generation_time long std dev 不相等 gen_time.long_std_dev:%02x  geneartion_time->long_std_dev:%02x",gen_time.long_std_dev,
                        generation_time->long_std_dev);
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
                //goto next;
            }
            else{
                wave_printf(MSG_DEBUG,"expiry time 不相等 %s %d",__FILE__,__LINE__);
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
        init_gen_loc = true;
        if(location != NULL){
            if(gen_loc.latitude == location->latitude){
                res = SUCCESS;
                //goto next;
            }
            else{
                wave_printf(MSG_DEBUG,"location  不相等 %s %d",__FILE__,__LINE__);
                res = INVALID_INPUT;
                goto next;
            }
            if(gen_loc.longitude == location->longitude){
                res = SUCCESS;
                //goto next;
            }
            else{
                res = INVALID_INPUT;
                goto next;
            }
        }
    }
    else if(location != NULL){
        init_gen_loc = true;
        gen_loc.longitude = location->longitude;
        gen_loc.latitude = location->latitude;
    }
    if(init_gen_loc == false){
        res = INVALID_INPUT;
        goto next;
    }
    if(gen_loc.latitude > 900000000 || gen_loc.latitude < -900000000 ||
            gen_loc.longitude > 1800000000 || gen_loc.longitude < -1800000000){
        res = SENDER_LOCATION_UNAVAILABLE;
        wave_printf(MSG_DEBUG,"location 超出范围 %s %d",__FILE__,__LINE__);
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
            
            break;
        case CERTIFICATE_CHAIN:
            temp_certs_chain.certs = (certificate*)malloc(sizeof(certificate) * s_data.signer.u.certificates.len);
            if(temp_certs_chain.certs == NULL){
                res = FAILURE;
                wave_malloc_error();
                goto end;
            }
            memset(temp_certs_chain.certs,0,sizeof(struct certificate) * s_data.signer.u.certificates.len);
            temp_certs_chain.len = s_data.signer.u.certificates.len;
            for(i=0;i<temp_certs_chain.len;i++){
                if(certificate_cpy(temp_certs_chain.certs+i,s_data.signer.u.certificates.buf+i)){
                    res = FAILURE;
                    goto end;
                }
            }
            if( res = cme_construct_certificate_chain(sdb,ID_CERTIFICATE,NULL,&temp_certs_chain,false,max_cert_chain_len,
                        &certs_chain,&permissions,&geo_scopes,last_recieve_crl_times,&times,&verifieds) ){
                goto end;
            }
            break;
        case CERTIFICATE:
            temp_certs_chain.certs = (struct certificate*)malloc(sizeof(struct certificate));
            if(temp_certs_chain.certs == NULL){
                res = FAILURE;
                wave_malloc_error();
                goto end;
            }
            memset(temp_certs_chain.certs,0,sizeof(struct certificate));
            if( certificate_cpy(temp_certs_chain.certs,&s_data.signer.u.certificate)){
                res = FAILURE;
                goto end;
            }
            temp_certs_chain.len = 1;
            if( res = cme_construct_certificate_chain(sdb,ID_CERTIFICATE,NULL,&temp_certs_chain,false,max_cert_chain_len,
                        &certs_chain,&permissions,&geo_scopes,last_recieve_crl_times,&times,&verifieds) ){
                goto end;
            }
            break;
        default:
            wave_error_printf("出现了不可能的直哦 %s %d",__FILE__,__LINE__);
            res = FAILURE;
            goto end;
    }

    if( res = sec_check_certificate_chain_consistency(sdb,&certs_chain,&permissions,&geo_scopes)){
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
    time(&now);
    for(i=0;i<times.len;i++){
        if ( *(times.times+i) < now-overdue_crl_tolerance/US_TO_S ){
             wave_printf(MSG_DEBUG,"next_expected_crl :%us  now :%us  overdue_crl_tolerance :%llus",
                                *(times.times+i),now,overdue_crl_tolerance/US_TO_S);
            res = OVERDUE_CRL;
            goto end;
        }
    } 
    cert = certs_chain.certs;
    if( certificate_get_start_time(cert,&start_validity)){
            res = FAILURE;
            wave_printf(MSG_DEBUG,"获取证书的开始有效时间错误  %s %d",__FILE__,__LINE__);
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
    if(init_gen_loc == true && geo_scopes.regions != NULL){
        if(!two_d_location_in_region(&gen_loc,geo_scopes.regions)){
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
        case PSID_SSP:
            for(i=0;i<permission->u.psid_ssp_array.len;i++){
                if(m_psid == (permission->u.psid_ssp_array.buf+i)->psid)
                    break;
            }
            if(i == permission->u.psid_ssp_array.len){
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
        time(&now);
        float threshold = normal_distribution_calculate_probability(  (float)generation_time->time, (float)pow(LOG_STD_DEV_BASE,generation_time->long_std_dev),
                            (float)generation_time->time, (float)(now*US_TO_S) );
        if(  threshold > generation_threshold ){
            printf("threshold  :%f   generation threshold  %f\n",threshold,generation_threshold);
            res = DATA_EXPIRED_BASE_ON_EXPIRY_TIME;
            goto end;
        }
        //请核实下我写对没有
        threshold = (float)normal_distribution_calculate_probability( (float)generation_time->time,(float)pow(LOG_STD_DEV_BASE,generation_time->long_std_dev),
                            (float)(now*US_TO_S),(float)generation_time->time+accepte_time);
        if( threshold > accepte_threshold){
            res = FUTURE_DATA;
            printf("threshold  :%f accepte threshold  %f\n",threshold,accepte_threshold);
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
        time(&now);
        float threshold = normal_distribution_calculate_probability( (float)(now*US_TO_S),(float)(1000),(float)exprity_time,(float)(now*US_TO_S));
        if( threshold > exprity_threshold){
            res = DATA_EXPIRED_BASE_ON_EXPIRY_TIME;
            printf("threshold :%f exprity threshold  %f\n",threshold,exprity_threshold);
            goto end;
        }
    }
    string_free(&string);
    if( signed_data_2_string(&s_data,&string,type) ){
         res = FAILURE;
         wave_printf(MSG_DEBUG,"signed_data_2_string 失败 %s %d",__FILE__,__LINE__);
         goto end;
    }
    if( detect_reply){
        res_temp = cme_reply_detection(sdb,lsis,&string);
        if(res_temp == FAILURE){
            res = FAILURE;
            wave_printf(MSG_DEBUG,"cme_reply_detection 失败 %s %d",__FILE__,__LINE__);
            goto end;
        }
        if( REPLAY ==  res_temp ){
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
        /*因为上面一个sec_verify_chain_signature 自己会自动增加证书，所以我这里没有按照协议要求在增加
        for(i=0;i<certs_chain.len;i++){
            cert = certs_chain.certs+i;
            cme_add_certificate(sdb,cert,true);
        }
        */
        //协议上没说，这个我想应该是这样
        if(send_cert != NULL){
            certificate_cpy(send_cert,certs_chain.certs);
        }
    }
end:
    certificate_chain_free(&certs_chain);
    certificate_chain_free(&temp_certs_chain);
    cme_permissions_array_free(&permissions);
    geographic_region_array_free(&geo_scopes);
    verified_array_free(&verifieds);
    signed_data_free(&s_data,type);
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

    if( string_2_crl(crl,&mycrl) <= 0){
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
            wave_printf(MSG_WARNING,"time : %u  now :%u overdue %u %s %d",
                    *(times.times+i),now,overdue_crl_tolerance,__FILE__,__LINE__);
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

    if(tobesigned_crl_2_string(&mycrl.unsigned_crl,&temp_string)){
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
    cme_permissions_array_free(&permissions_array);
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
    string temp_string,pubkey_x,pubkey_y,prikey,hashed_string,signature_string,uncompressed_x,uncompressed_y;
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
    INIT(uncompressed_x);
    INIT(uncompressed_y);
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
        if(veri_pub_key->algorithm != ECDSA_NISTP256_WITH_SHA256 && veri_pub_key->algorithm != ECDSA_NISTP224_WITH_SHA224){
            wave_error_printf("这里怎么可能是加密的算法，这个是认证钥匙，应该是签名的");
            res = FAILURE;
            goto end;
        }
        if(elliptic_curve_point_2_uncompressed(veri_pub_key->algorithm,&veri_pub_key->u.public_key,&uncompressed_x,&uncompressed_y)){
            res = FAILURE;
            goto end;
        }
        for(i=0;i<pubkey_x.len;i++){
            if( *(uncompressed_x.buf +i) != *(pubkey_x.buf+i)){
                        break;
            }
        }
        if( i != pubkey_x.len){
            res = INCONSISITENT_KEYS_IN_REQUEST;
            goto end;
        }

        for(i=0;i<pubkey_y.len;i++){
            if( *(uncompressed_y.buf +i) != *(pubkey_y.buf+i)){
                        break;
            }
        }
        if( i != pubkey_y.len){
            res = INCONSISITENT_KEYS_IN_REQUEST;
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
    if( signature_generation(&cert_request.signature,veri_pub_key->algorithm,NO,&temp_string,&prikey)){
        res = FAILURE;
        goto end;
    }
    
    cert_request.signer.type = type;
    if(type == CERTIFICATE){
        certificate_cpy(&cert_request.signer.u.certificate,&csr_cert);
    }
     
    string_free(&temp_string);
    string_free(&hashed_string);
    certificate_request_2_string(&cert_request,&temp_string);
    crypto_HASH_256(&temp_string,&hashed_string);

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
    string_free(&uncompressed_x);
    string_free(&uncompressed_y);
    elliptic_curve_point_free(&point);
    certificate_request_free(&cert_request);
    certificate_chain_free(&cert_chain);
    return res;
}
result sec_certificate_response_processing(struct sec_db* sdb,cmh cmh,string* data,
                
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

    if( string_2_sec_data(data,&s_data) <= 0){
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
        if( string_2_tobe_encrypted_certificate_request_error(&de_data,&cert_req_error) <= 0){
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
        if(string_2_tobe_encrypted_certificate_response(&de_data,&cert_resp) <=0 ){
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

    sec_data.u.signed_wsa.unsigned_wsa.generation_time.time = time(NULL);
    sec_data.u.signed_wsa.unsigned_wsa.generation_time.long_std_dev = 0xff;

    sec_data.u.signed_wsa.unsigned_wsa.generation_location.latitude = td_location.latitude;
    sec_data.u.signed_wsa.unsigned_wsa.generation_location.longitude = td_location.longitude;
    sec_data.u.signed_wsa.unsigned_wsa.generation_location.elevation[0] = 0;
    sec_data.u.signed_wsa.unsigned_wsa.generation_location.elevation[1] = 0;

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
            algorithm = cert.unsigned_certificate.version_and_type.verification_key.algorithm;
            break;
        case 3:
            algorithm = cert.unsigned_certificate.u.no_root_ca.signature_alg;
            break;
        default:
            wave_error_printf("出现了不可能出现的指 %s %d ",__FILE__,__LINE__);
            ret = FAILURE;
            goto fail;
    }
    if(algorithm != ECDSA_NISTP224_WITH_SHA224 || algorithm != ECDSA_NISTP256_WITH_SHA256){
        wave_error_printf("这里的协议类型都不等于我们要求的这里有问题,我们这里暂时不支持其他的加密算法");
        ret = -1;
        goto fail;
    }
    if( signature_generation(&sec_data.u.signed_wsa.signature,algorithm,NO,&encoded_tbs,&privatekey)){
        ret = -1;
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
    string permission_indices, encoded_tbs, digest;
    time64 g_time = 0;
    time64 e_time = 0;
    pk_algorithm algorithm;
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
    INIT(encoded_tbs);
    INIT(digest);
    INIT(ser_info_array);

    if(string_2_sec_data(wsa, &sec_data) <= 0 ){
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
    if(sec_data.protocol_version != 2 || sec_data.type != SIGNED_WSA || sec_data.u.signed_wsa.signer.type != CERTIFICATE_CHAIN
                || sec_data.u.signed_wsa.unsigned_wsa.generation_time.time > sec_data.u.signed_wsa.unsigned_wsa.expire_time){
        ret = INVALID_INPUT;
        goto end;
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
    if(three_d_location_in_region(&location, &regions.regions[0]))
        ret = WSA_GENERATED_OUTSIDE_CERTIFICATED_VALIDITY_REGION;

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
    if(tobesigned_wsa_2_string(&sec_data.u.signed_wsa.unsigned_wsa, &encoded_tbs)){
        wave_error_printf("编码失败");
        ret = FAILURE;
        goto end;
    }

    struct certificate *cert = &chain.certs[0];
    switch(cert->version_and_type){
        case 2:
            algorithm = cert->unsigned_certificate.version_and_type.verification_key.algorithm;
            break;
        case 3:
            algorithm = cert->unsigned_certificate.u.no_root_ca.signature_alg;
            break;
        default:
            wave_error_printf("出现了不可能出现的指 %s %d ",__FILE__,__LINE__);
            ret = FAILURE;
            goto end;
    }
    if(algorithm == ECDSA_NISTP224_WITH_SHA224){
        if(crypto_HASH_224(&encoded_tbs, &digest)){
            wave_error_printf("hash 224失败");
            goto end;
        }
    }
    else if(algorithm == ECDSA_NISTP256_WITH_SHA256){
        if(crypto_HASH_256(&encoded_tbs, &digest)){
            wave_error_printf("hash 256失败");
            goto end;
        }
    }
    else{
        wave_error_printf("不是签名方法，错误");
        goto end;
    }

    ret = sec_verify_chain_signature(sdb, &chain, &verified, &digest, &sec_data.u.signed_wsa.signature);
    if(ret != SUCCESS)
        goto end;
    certificate_cpy(certificate, &chain.certs[0]);
    ret = SUCCESS;

end:
    for(i = 0; i < len; i++){
        if(results->result[i] != UNSECURED)
            results->result[i] = ret;
    }

    certificate_chain_free(&chain);
    certificate_chain_free(&tmp_chain);
    cme_permissions_array_free(&cme_permissions);
    geographic_region_array_free(&regions);
    verified_array_free(&verified);
    dot2_service_info_array_free(&ser_info_array);
    sec_data_free(&sec_data);
    string_free(&permission_indices);
    string_free(&encoded_tbs);
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
result sec_check_chain_geographic_consistency(struct sec_db* sdb,
                        struct geographic_region_array* regions){
    result ret = SUCCESS;
    int i = 0;
    for(i = 0; i < regions->len-1; i++){
        if(geographic_region_in_geographic_region(regions->regions+i, regions->regions+i+1)){
            ret = INCONSISTENT_GEOGRAPHIC_SCOPE;
            return ret;
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
bool static verify_signature_no_fast(pk_algorithm algorithm,string* pubkey_x,string* pubkey_y,string* r,string *s,string *mess){
    if(algorithm != ECDSA_NISTP224_WITH_SHA224 && algorithm != ECDSA_NISTP256_WITH_SHA256){
        wave_error_printf("参数有问题 %s %d",__FILE__,__LINE__);
        return false;
    }

    bool res = true;

    if(algorithm == ECDSA_NISTP224_WITH_SHA224){
        res = crypto_ECDSA_224_verify_message(pubkey_x,pubkey_y,r,s,mess);
        goto end;
    }
    else{
        res = crypto_ECDSA_256_verify_message(pubkey_x,pubkey_y,r,s,mess);
        goto end;
    }
end:
    return res;
}
bool static verify_signature_fast(pk_algorithm algorithm,string* pubkey_x,
                    string* pubkey_y,string* r_x,string* r_y,string* s,string* mess){
    if(algorithm != ECDSA_NISTP224_WITH_SHA224 && algorithm != ECDSA_NISTP256_WITH_SHA256){
        wave_error_printf("参数有问题 %s %d",__FILE__,__LINE__);
        return false;
    }
    bool res = true;

    if(algorithm == ECDSA_NISTP224_WITH_SHA224){
        res = crypto_ECDSA_224_FAST_verify_message(pubkey_x,pubkey_y,mess,r_x,r_y,s);
        goto end;
    }
    else{
        res = crypto_ECDSA_256_FAST_verify_message(pubkey_x,pubkey_y,mess,r_x,r_y,s);
        goto end;
    }
end:
    return res;
}
bool static verify_signature(pk_algorithm algorithm,signature* sig,string *pubkey_x,string* pubkey_y,string *mess){
    if(algorithm != ECDSA_NISTP224_WITH_SHA224 && algorithm != ECDSA_NISTP256_WITH_SHA256){
        wave_error_printf("参数有问题 %s %d",__FILE__,__LINE__);
        return false;
    }
    string r,s,r_x,r_y;
    elliptic_curve_point* point;
    bool res = true;

    INIT(r);
    INIT(s);
    INIT(r_x);
    INIT(r_y);

    s.len = sig->u.ecdsa_signature.s.len;
    s.buf = (u8*)malloc(s.len);
    if(s.buf == NULL){
        wave_malloc_error();
        res = false;
        goto end;
    }
    memcpy(s.buf,sig->u.ecdsa_signature.s.buf,s.len);

    point = &sig->u.ecdsa_signature.r;
    if(point->type == X_COORDINATE_ONLY){
        r.len = point->x.len;
        r.buf = (u8*)malloc(r.len);
        if(r.buf == NULL){
            wave_malloc_error();
            res = false;
            goto end;
        }
        memcpy(r.buf,point->x.buf,r.len);
        printf("r.len :%d algorithm :%d  %s %d\n",r.len,algorithm,__FILE__,__LINE__);
        res = verify_signature_no_fast(algorithm,pubkey_x,pubkey_y,&r,&s,mess);
        goto end;
    }
    else if(point->type == UNCOMPRESSED){
        r_x.len = point->x.len;
        r_y.len = point->u.y.len;
        r_x.buf = (u8*)malloc(r_x.len);
        r_y.buf = (u8*)malloc(r_y.len);
        if(r_x.buf == NULL || r_y.buf == NULL){
            wave_malloc_error();
            res = false;
            goto end;
        }
        memcpy(r_x.buf,point->x.buf,r_x.len);
        memcpy(r_y.buf,point->u.y.buf,r_y.len);

        res = verify_signature_fast(algorithm,pubkey_x,pubkey_y,&r_x,&r_y,&s,mess);
        goto end;
    }
    else{
       if( elliptic_curve_point_2_uncompressed(algorithm,point,&r_x,&r_y)){
            wave_error_printf("解压失败  %s %d",__FILE__,__LINE__);
            res = false;
            goto end;
       }
       res = verify_signature_fast(algorithm,pubkey_x,pubkey_y,&r_x,&r_y,&s,mess);
       goto end;
    }
end:
    string_free(&r);
    string_free(&r_x);
    string_free(&r_y);
    string_free(&s);
    return res;
}
int static implicit_certificate_get_pubkey(struct sec_db* sdb,certificate* cert,string* pubkey_x,string* pubkey_y,pk_algorithm *algorithm){
    int res = 0;
    certificate ca_cert;
    string ca_x,ca_y;
    string pu_x,pu_y;
    string e;

    INIT(ca_cert);
    INIT(ca_x);
    INIT(ca_y);
    INIT(pu_x);
    INIT(pu_y);
    INIT(e);
    
    if(cert->version_and_type != 3){
        wave_error_printf("传经来的不是隐士证书  %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    if( find_cert_prikey_by_cmh(sdb,1,&ca_cert,NULL)){
        wave_error_printf("没有ca证书 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    if(ca_cert.version_and_type == 3){
        wave_error_printf("ca 证书竟然是隐士的  %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    if(algorithm != NULL)
        *algorithm = ca_cert.unsigned_certificate.version_and_type.verification_key.algorithm;

    if(elliptic_curve_point_2_uncompressed(ca_cert.unsigned_certificate.version_and_type.verification_key.algorithm,
                        &ca_cert.unsigned_certificate.version_and_type.verification_key.u.public_key,&ca_x,&ca_y)){
        res = -1;
        goto end;
    } 
    if(elliptic_curve_point_2_uncompressed(cert->unsigned_certificate.u.no_root_ca.signature_alg,
                        &cert->u.reconstruction_value,&pu_x,&pu_y)){
        res = -1;
        goto end;
    }
    e.len = 8;
    e.buf = (u8*)malloc(e.len);
    if(e.buf == NULL){
        wave_malloc_error();
        res = -1;
        goto end;
    }
    memcpy(e.buf,cert->unsigned_certificate.u.no_root_ca.signer_id.hashedid8,e.len);

    if(cert->unsigned_certificate.u.no_root_ca.signature_alg != ECDSA_NISTP256_WITH_SHA256){
        wave_error_printf("隐士证书，我们支持256 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    if(crypto_cert_pk_extraction_SHA256(&ca_x,&ca_y,&pu_x,&pu_y,&e,pubkey_x,pubkey_y)){
        res = -1;
        goto end;
    }
    goto end;
end:
    string_free(&ca_x);
    string_free(&ca_y);
    string_free(&pu_x);
    string_free(&pu_y);
    string_free(&e);
    certificate_free(&ca_cert);
    return res;
}
//这里的证书链，是后面一个签发前面一个？？？
result sec_verify_chain_signature(struct sec_db* sdb,
        struct certificate_chain* cert_chain,
        struct verified_array* verified_array,
        string* digest,
        signature* signature){
    result res = SUCCESS;
    string temp,pubkey_x,pubkey_y,hashed;
    pk_algorithm algorithm;
    certificate *cert;

    INIT(temp);
    INIT(pubkey_x);
    INIT(pubkey_y);
    INIT(hashed);

    int len = cert_chain->len; 
    int i = 0;
    for(i = 0; i < len; i++){
        if(verified_array->verified[i] == false && cert_chain->certs[i].version_and_type == 2){
            //调用crypto++的函数来验证
            if(i == cert_chain->len - 1){
                wave_printf(MSG_ERROR,"这里应该怎么弄？？，我直接认为头都不被信任 返回错误 %s %d",__FILE__,__LINE__);
                res = CERTIFICATE_VERIFICATION_FAILED;
                goto end;
            }
            cert = cert_chain->certs + i+1;
            string_free(&pubkey_x);
            string_free(&pubkey_y);
            string_free(&hashed);
            if(elliptic_curve_point_2_uncompressed(cert->unsigned_certificate.version_and_type.verification_key.algorithm,
                        &cert->unsigned_certificate.version_and_type.verification_key.u.public_key,&pubkey_x,&pubkey_y)){
                res = FAILURE;
                goto end;
            }
            algorithm = cert->unsigned_certificate.version_and_type.verification_key.algorithm;

            cert = cert_chain->certs + i;
            string_free(&temp);
            if( tobesigned_certificate_2_string(&cert->unsigned_certificate,&temp,cert->version_and_type)){
                res = FAILURE;
                goto end;
            }
            if(algorithm == ECDSA_NISTP224_WITH_SHA224){
                if(crypto_HASH_224(&temp,&hashed)){
                    res = -1;
                    goto end;
                }
            }
            else if(algorithm == ECDSA_NISTP256_WITH_SHA256){
                if(crypto_HASH_256(&temp,&hashed)){
                    res = -1;
                    goto end;
                }
            }
            else {
                wave_error_printf("出现了不可能的指 %s %d",__FILE__,__LINE__);
                res = -1;
                goto end;
            }
        
            if( verify_signature(cert->unsigned_certificate.u.no_root_ca.signature_alg,&cert->u.signature,&pubkey_x,&pubkey_y,
                        &hashed) == false){
                res = CERTIFICATE_VERIFICATION_FAILED;
                goto end;
            }            
        }
    }

    if(digest == NULL || signature == NULL){
        res = SUCCESS;
        goto end;
    }

    string_free(&pubkey_x);
    string_free(&pubkey_y);
    if(cert_chain->certs[0].version_and_type == 2){
        //验证报文的签名
        cert = cert_chain->certs;    
        if(elliptic_curve_point_2_uncompressed(cert->unsigned_certificate.version_and_type.verification_key.algorithm,
                        &cert->unsigned_certificate.version_and_type.verification_key.u.public_key,&pubkey_x,&pubkey_y)){
            res = FAILURE;
            goto end;
        }
       algorithm = cert->unsigned_certificate.version_and_type.verification_key.algorithm; 
    }

    else if(cert_chain->certs[0].version_and_type == 3){
       if(implicit_certificate_get_pubkey(sdb,cert_chain->certs,&pubkey_x,&pubkey_y,&algorithm)){
            res = FAILURE;
            goto end;
       } 
    }

    if( verify_signature(algorithm,signature,&pubkey_x,&pubkey_y,digest) == false){
            res = VERIFICATION_FAILURE;
            goto end;
    }

    for(i = 0; i < len; i++){
        if(verified_array->verified[i] == false)
            cme_add_certificate(sdb, &cert_chain->certs[i], true);
    }
    goto end;
end:
    string_free(&temp);
    string_free(&pubkey_x);
    string_free(&pubkey_y);
    string_free(&hashed);
    return res;
}
result sec_decrypt_data(struct sec_db* sdb,string* encrypted_data,cmh cmh,   
                            content_type* type,string* data){
    result res = SUCCESS;
    struct encrypted_data encrypteddata;
    struct recipient_info* recinfo;
    struct certificate cert;
    struct hashedid8 hashed;
    struct tobe_encrypted tobe_en;
    string encrypted_key,ephe_x,ephe_y,tag,prikey,decrypted_key,ciphertext,nonce,plaintext;
    int i;

    INIT(encrypteddata);
    INIT(tobe_en);
    INIT(cert);
    INIT(encrypted_key);
    INIT(ephe_x);
    INIT(ephe_y);
    INIT(tag);
    INIT(prikey);
    INIT(decrypted_key);
    INIT(ciphertext);
    INIT(nonce);
    INIT(plaintext);

    if(string_2_encrypted_data(encrypted_data,&encrypteddata) <= 0){
        res = -1;
        goto end;
    }
    if( find_cert_prikey_by_cmh(sdb,cmh,&cert,&prikey)){
        wave_error_printf("查找失败 这里按照协议我应该查找\
cmh存储的是证书和cmh存储的一对钥匙 但是我只做了前者的茶学%s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    if(certificate_2_hashedid8(&cert,&hashed)){
        res = -1;
        goto end;
    }
    for(i=0;i<encrypteddata.recipients.len;i++){
        recinfo = encrypteddata.recipients.buf+i;
        if(hashedid8_cmp(&recinfo->cert_id,&hashed) == 0){
            if(cert.unsigned_certificate.cf & ENCRYPTION_KEY){
                if(encrypteddata.symm_algorithm != cert.unsigned_certificate.flags_content.encryption_key.u.ecies_nistp256.supported_symm_alg){
                    continue;
                }
                break;
            }
        }
    }
    if(i == encrypteddata.recipients.len){
        res = NO_DECRYPTION_CERTIFICATE_FOUND;
        goto end;
    }
    if(cert.unsigned_certificate.flags_content.encryption_key.algorithm != ECIES_NISTP256){
        wave_error_printf("不是我们支持的ECIES——256 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    encrypted_key.len = recinfo->u.enc_key.c.len;
    tag.len = 20;
    if( elliptic_curve_point_2_uncompressed(ECIES_NISTP256,&recinfo->u.enc_key.v,&ephe_x,&ephe_y)){
        res = -1;
        goto end;
    }
    encrypted_key.buf = (u8*)malloc(encrypted_key.len);
    tag.buf = (u8*)malloc(tag.len);
    if(encrypted_key.buf == NULL || tag.buf == NULL){
        res = -1;
        wave_malloc_error();
        goto end;
    }
    memcpy(encrypted_key.buf,recinfo->u.enc_key.c.buf,encrypted_key.len);
    memcpy(tag.buf,recinfo->u.enc_key.t,tag.len);

    if( crypto_ECIES_decrypto_message(&encrypted_key,&ephe_x,&ephe_y,&tag,&prikey,&decrypted_key)){
        res = -1;
        goto end;
    }
    if(encrypteddata.symm_algorithm != AES_128_CCM){
        res = -1;
        wave_error_printf("出现了不支持的协议 %s %d",__FILE__,__LINE__);
        goto end;
    }
    ciphertext.len = encrypteddata.u.ciphertext.ccm_ciphertext.len;
    nonce.len = 12;
    ciphertext.buf = (u8*)malloc(ciphertext.len);
    nonce.buf = (u8*)malloc(nonce.len);
    if(ciphertext.buf == NULL || nonce.buf == NULL){
        wave_malloc_error();
        res = -1;
        goto end;
    }
    memcpy(nonce.buf,encrypteddata.u.ciphertext.nonce,nonce.len);
    memcpy(ciphertext.buf,encrypteddata.u.ciphertext.ccm_ciphertext.buf,ciphertext.len);


    if( crypto_AES_128_CCM_decrypto_message(&ciphertext,&decrypted_key,&nonce,&plaintext)){
        res = -1;
        goto end;
    }
    if(string_2_tobe_encrypted(&plaintext,&tobe_en) <= 0){
        res = -1;
        goto end;
    }
    if(type != NULL){
        *type = tobe_en.type;
    }
    if(data != NULL){
        string_cpy(data,&plaintext);
    }
    goto end;

end:
    encrypted_data_free(&encrypted_data);
    tobe_encrypted_free(&tobe_en);
    certificate_free(&cert);
    string_free(&encrypted_key);
    string_free(&ephe_x);
    string_free(&ephe_y);
    string_free(&tag);
    string_free(&prikey);
    string_free(&decrypted_key);
    string_free(&ciphertext);
    string_free(&nonce);
    string_free(&plaintext);
    return res;
}
result sec_certificate_request_error_verification(struct sec_db* sdb,tobe_encrypted_certificate_request_error* cert_req_error){
    result res = SUCCESS;
    struct certificate_chain chain,temp_certs_chain;
    struct cme_permissions_array permissions;
    struct geographic_region_array geoscopes;
    struct time32_array last_crl,next_crl;
    struct verified_array verified;
    enum identifier_type type;
    string identifier,digest;
    time_t t;
    int i; 

    INIT(chain);
    INIT(temp_certs_chain);
    INIT(permissions);
    INIT(geoscopes);
    INIT(last_crl);
    INIT(next_crl);
    INIT(verified);
    INIT(identifier);
    INIT(digest);

    if(cert_req_error->signer.type == CERTIFICATE_DIGEST_WITH_ECDSAP224){
        res = INVAILD_CA_SIGNATURE_ALGORITHM;
        goto end;
    }
    if(cert_req_error->signer.type == CERTIFICATE_DIGEST_WITH_ECDSAP256){
        type = ID_HASHEDID8;
        hashedid8_2_string(&cert_req_error->signer.u.digest,&identifier);
        res = cme_construct_certificate_chain(sdb,type,&identifier,NULL,false,255,&chain,&permissions,&geoscopes,&last_crl,&next_crl,&verified);
    }
    else if(cert_req_error->signer.type == CERTIFICATE){
        type = ID_CERTIFICATE;
        temp_certs_chain.len = 1;
        if( temp_certs_chain.certs = (certificate*)malloc(sizeof(certificate) * 1)){
            wave_malloc_error();
            res = FAILURE;
            goto end;
        }
        certificate_cpy(temp_certs_chain.certs,&cert_req_error->signer.u.certificate);
        res = cme_construct_certificate_chain(sdb,type,NULL,&temp_certs_chain,false,255,&chain,&permissions,
                   &geoscopes,&last_crl,&next_crl,&verified);

    }
    else if(cert_req_error->signer.type == CERTIFICATE_CHAIN){
        type = ID_CERTIFICATE;
        temp_certs_chain.len = cert_req_error->signer.u.certificates.len;
        if( temp_certs_chain.certs = (certificate*)malloc(sizeof(certificate) * temp_certs_chain.len)){
            wave_malloc_error();
            res = FAILURE;
            goto end;
        }
        for(i = 0;i<temp_certs_chain.len;i++){
            certificate_cpy(temp_certs_chain.certs+i,cert_req_error->signer.u.certificates.buf+i);
        }
        res = cme_construct_certificate_chain(sdb,type,NULL,&temp_certs_chain,false,255,&chain,&permissions,
                   &geoscopes,&last_crl,&next_crl,&verified);

    }
    else{
        wave_error_printf("出现了不可能的指 %s %d",__FILE__,__LINE__);
        res = -1;
        goto end;
    }
    time(&t);
    for(i=0;i<next_crl.len;i++){
        if(*(next_crl.times+i) < t){
            res = OVERDUE_CRL;
            goto end;
        }
    }
    if( (res = sec_check_certificate_chain_consistency(sdb,&chain,&permissions,&geoscopes)) ){
        goto end;
    }
    //这个地方我们求digest我不知道求对没有，，请核实哈
    digest.len = 10 + 1;
    digest.buf = (u8*)malloc(digest.len);
    if(digest.buf == NULL){
        wave_malloc_error();
        res = -1;
        goto end;
    }
    memcpy(digest.buf,cert_req_error->request_hash,10);
    *(digest.buf + 10) = (u8)cert_req_error->reason;
    

    res = sec_verify_chain_signature(sdb,&chain,&verified,&digest,&cert_req_error->signature);
    goto end;
end:
    certificate_chain_free(&chain);
    certificate_chain_free(&temp_certs_chain);
    cme_permissions_array_free(&permissions);
    geographic_region_array_free(&geoscopes);
    time32_array_free(&last_crl);time32_array_free(&next_crl);
    verified_array_free(&verified);
    string_free(&identifier);
    string_free(&digest);
    return res;
}
result sec_certificate_response_verification(struct sec_db* sdb,tobe_encrypted_certificate_response* cert_resp){
    result res = SUCCESS;
    struct certificate_chain chain,temp_certs_chain;
    struct cme_permissions_array permissions;
    struct geographic_region_array geoscopes;
    struct time32_array last_crl,next_crl;
    struct verified_array verified;
    struct crl *crl;
    string temp;
    time_t t;
    int i;
    
    INIT(chain);
    INIT(temp_certs_chain);
    INIT(permissions);
    INIT(geoscopes);
    INIT(last_crl);
    INIT(next_crl);
    INIT(verified);
    INIT(temp);

    for(i=0;i<cert_resp->crl_path.len;i++){
        crl = cert_resp->crl_path.buf+i;
        string_free(&temp);
        if(crl_2_string(crl,&temp)){
            res = -1;
            goto end;
        }
        res = sec_crl_verification(sdb,&temp,0,NULL,NULL,NULL);
        if(res != SUCCESS)
            goto end;
        cme_add_crlinfo(sdb,crl->unsigned_crl.type,crl->unsigned_crl.crl_series,&crl->unsigned_crl.ca_id,crl->unsigned_crl.crl_serial,
                            crl->unsigned_crl.start_period,crl->unsigned_crl.issue_date,crl->unsigned_crl.next_crl);
    }
    
    temp_certs_chain.len = cert_resp->certificate_chain.len;
    if( temp_certs_chain.certs = (certificate*)malloc(sizeof(certificate) * temp_certs_chain.len)){
        wave_malloc_error();
        res = -1;
        goto end;
    }
    for(i = 0;i<temp_certs_chain.len;i++){
        certificate_cpy(temp_certs_chain.certs+i,cert_resp->certificate_chain.buf+i);
    }
    res = cme_construct_certificate_chain(sdb,ID_CERTIFICATE,NULL,&temp_certs_chain,false,255,&chain,&permissions,
                &geoscopes,&last_crl,&next_crl,&verified);
    if(res != SUCCESS)
        goto end;

    time(&t);
    for(i=0;i<next_crl.len;i++){
        if(*(next_crl.times+i) < t){
            res = OVERDUE_CRL;
            goto end;
        }
    }
    
    if( (res = sec_check_certificate_chain_consistency(sdb,&chain,&permissions,&geoscopes)) ){
        goto end;
    }
    /*********以下的请看协议，我不是很确定****************/
    for(i=0;i<cert_resp->crl_path.len;i++){
        crl = cert_resp->crl_path.buf+i;
        //这里这个证书连第一个应该是我们申请的把。。。
        if(hashedid8_cmp(&crl->unsigned_crl.ca_id,&cert_resp->certificate_chain.buf->unsigned_certificate.u.no_root_ca.signer_id)){
            if(crl->unsigned_crl.crl_series == cert_resp->certificate_chain.buf->unsigned_certificate.crl_series){
                break;
            }
        }
    }
    if(i == cert_resp->crl_path.len){
        res = NO_RELEVANT_CRL_PROVIDED;
        goto end;
    }
    /************************************/
    /*********接下来的我感觉协议有些出入，自己按照自己的逻辑做的************/
    res = sec_verify_chain_signature(sdb,&chain,&verified,NULL,NULL);
    goto end; 
end:
    certificate_chain_free(&chain);
    cme_permissions_array_free(&permissions);
    geographic_region_array_free(&geoscopes);
    time32_array_free(&last_crl);
    time32_array_free(&next_crl);
    verified_array_free(&verified);
    string_free(&temp);
    certificate_chain_free(&temp_certs_chain);
    return res;
}
result get_current_location(two_d_location *td_location){
    if(td_location == NULL)
        return -1;
    td_location->latitude = 0;
    td_location->longitude = 0;
    return 0;
}

u32 distance_with_two_d_location(two_d_location* a,two_d_location* b){
    double r = 6371000;
    double x1,y1,x2,y2;
    u32 res;
    x1 = a->longitude/1000/180*M_PI;
    y1 = a->latitude/1000/180*M_PI;
    x2 = b->longitude/1000/180*M_PI;
    y2 = b->latitude/1000/180*M_PI;
    
    res = (u32)(r* acos( cos(y2) * cos(y1) *cos(x2-x1) + sin(y2) *sin(y1)));
    return res;
}
