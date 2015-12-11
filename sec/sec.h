#ifndef SEC_H
#define SEC_H
#include <linux/types.h>
#include"pssme/pssme_db.h"
#include"cme/cme_db.h"
#include"cme/cme.h"
#include"pssme/pssme.h"



enum sign_with_fast_verification{
    YES_UNCOMPRESSED = 0,
    YES_COMPRESSED = 1,
    NO = 2,
};
enum signed_data_signer_type{
    SIGNED_DATA_CERTIFICATE = 0,
    SIGNED_DATA_CERTIFICATE_DIGEST = 1,
    SIGNED_DATA_CERTIFICATE_CHAIN = 2,
};

typedef struct ssp_array{
    string *ssps;
    u8 len;
}ssp_array;

typedef struct result_array{
    result *result;
    u32 len;
}result_array;

struct region_type_array{
    region_type* types;
    u32 len;
};

void ssp_array_free(struct ssp_array* ptr);

void result_array_free(struct result_array* ptr);


/*
 * 签名数据
 *
 * @type：只能是signed signed_partial_payload signed_external_payload,其他返回错误。
 * @data:需要签名的data，编码好了的。
 * @exter_data:同上。
 * @psid:填写data的psid字段
 * @ssp：服务特殊权限，
 * @set_generation_time:是否要填写generation_time字段，
 * @generation_time:对应时间,这个结构题里面有，时间误差，填写255代表不知道。
 * @set_generation_location: 是否填写generation_location字段，
 * @generation_location:位置信息.
 * @set_expiry_time:是否要填写expiry_time字段
 * @expiry_time:过期时间。
 * @signer_type:签发这个数据的签名类型，
 * @cert_chain_len:如果是证书连，相关的长度，这个说明请看协议。
 * @cert_chain_max_len:证书连最长证书。
 * @fs_type:快速认证类型，
 * @compressed：ec点是否压缩
 *
 * @signed_data:填写好了数据，编码,输入到signed_data.
 * @len_of_cert_chain:该证书连的长度。
 */
result sec_signed_data(struct sec_db* sdb,
                cmh cmh,
                content_type type,string* data,
                string* exter_data,psid psid,
                string* ssp,
                bool set_generation_time, 
                time64_with_standard_deviation* generation_time,
                bool set_generation_location,
                three_d_location* location,
                bool set_expiry_time,
                time64 expiry_time,
                enum signed_data_signer_type signer_type,
                s32 cert_chain_len,
                u32 cert_chain_max_len,
                enum sign_with_fast_verification fs_type,
                bool compressed,
                
                string* signed_data,
                u32* len_of_cert_chain);


;

/*
 * 加密数据，参数参考协议
 */
result sec_encrypted_data(struct sec_db* sdb,
                content_type type,
                string* data,
                struct certificate_chain* certs,
                bool compressed,
                time64 time,
                
                string* encrypted_data,
                struct certificate_chain* failed_certs);


result sec_secure_data_content_extration(struct sec_db* sdb,
                string* recieve_data,cmh cmh,
                
                content_type *type,
                content_type *inner_type,
                string* data,
                string* signed_data,
                psid *psid,
                string* ssp,
                bool* set_generation_time,
                time64_with_standard_deviation *generation_time,
                bool* set_expiry_time,
                time64* expiry_time,
                bool* set_generation_location,
                three_d_location *location,
                certificate* send_cert);

/**
 * 验证数据的签名，
 * 参数参考协议.
 */
result sec_signed_data_verification(struct sec_db* sdb,
                cme_lsis lsis,
                psid *psid,
                content_type type,
                string* signed_data,
                string* external_data,
                u32 max_cert_chain_len,
                bool detect_reply,
                bool check_generation_time,
                time64 validity_period,
                time64_with_standard_deviation* generation_time,
                float generation_threshold,
                time64 accepte_time,
                float accepte_threshold,
                bool check_expiry_time,
                time64 exprity_time,
                float exprity_threshold,
                bool check_generation_location,
                two_d_location* location,
                u32 validity_distance,
                three_d_location* generation_location,
                time64 overdue_crl_tolerance,
                
                struct time32_array *last_recieve_crl_times,
                struct time32_array *next_expected_crl_times,
                certificate* send_cert);
/**
 * crl的签名验证
 */
result sec_crl_verification(struct sec_db* sdb,string* crl,time32 overdue_crl_tolerance,
                        
                struct time32_array* last_crl_times,
                struct time32_array* next_crl_times,
                certificate* send_cert);

enum transfer_type{
    EXPLICT = 1,
    IMPLICT = 2,
};
/*
 * 生成一个证书请求报,时间单位是秒
 * 参数请看协议
 */
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
                
                string* cert_request,
                certid10* request_hash);

result sec_certificate_response_processing(struct sec_db* sdb,
                cmh cmh,
                string* data,
                
                content_type* type,
                certid10 *request_hash,
                certificate_request_error_code* error,
                certificate* certificate,
                string* rec_value,
                bool *ack_request
                );

result sec_signed_wsa(struct sec_db* sdb,
                string* data,
                serviceinfo_array* permissions,
                time32 life_time,

                string* signed_wsa);

result sec_signed_wsa_verification(struct sec_db* sdb,
                string* wsa,
                
                result_array *result,
                string* wsa_data,
                ssp_array* ssp_array,
                time64_with_standard_deviation* generation_time,
                time64 *expiry_time,
                three_d_location* location,
                struct time32_array *last_crl_time,
                struct time32_array *next_crl_time,
                certificate* certificate);


result sec_check_certificate_chain_consistency(
                struct sec_db* sdb,
                struct certificate_chain* cert_chain,
                struct cme_permissions_array* permission_array,
                struct geographic_region_array* region);

result sec_check_chain_psids_consistency(struct sec_db* sdb,
                struct cme_permissions_array* permission_array);

result sec_check_chain_psid_priority_consistency(struct sec_db* sdb,
                struct cme_permissions_array* permission_array);

result sec_check_chain_geographic_consistency(struct sec_db* sdb,
                struct geographic_region_array* regions);

result sec_verify_chain_signature(struct sec_db* sdb,
                struct certificate_chain* cert_chain,
                struct verified_array* verified_array,
                string* digest,
                signature* signature);

result sec_decrypt_data(struct sec_db* sdb,
                string* encrypted_data,
                cmh cmh,
                
                content_type* type,
                string* data);

result sec_certificate_request_error_verification(struct sec_db* sdb,
                tobe_encrypted_certificate_request_error* cert_req_error);

result sec_certificate_response_verification(struct sec_db* sdb,
                tobe_encrypted_certificate_response* cert_resp);

/***************这后面的函数都是certificate的一些帮助接口，方便获取证书的相关信息******/
result get_current_location(two_d_location *td_location);
bool two_d_location_in_geographic_region(two_d_location* loc,geographic_region* region);
u32 distance_with_two_d_location(two_d_location* a,two_d_location* b);

//提取wsa中的serviceinfo
struct service_info{
    char           *serv;
    char           *psc;
    unsigned char  *ipv6_addr;
    __be16         *serv_port;
    unsigned char  *prov_mac_addr;
    signed char    *rcpi_thresh;
    unsigned char  *wsa_count_thresh;
    unsigned char  *wsa_count_thresh_interv;
    u64            *exp_crl_time;
};

struct dot2_service_info{
    psid psid;
    u8 priority;
};

struct dot2_service_info_array{
    struct dot2_service_info *service_infos;
    u8 len;
};

struct wsa_header_ext{
    unsigned char *repeat_rate;
    signed char   *tx_power;
    char          *_2d_location;
    char          *_3d_location;
    char          *advertiser_id;
    char          *country_string;
};

struct channel_info{
    unsigned char  *channel;
    char           *edca_set;
    unsigned char  *channel_access;
};

struct wra{
     char *wra;
     char *second_dns;
     unsigned char *gateway_mac_addr;
};
/* element id in wsa */
typedef enum{
    // WSA WAVE Elements
    EID_RESERVED = 0,
    EID_SERVINFO,
    EID_CHANINFO,
    EID_WRA,
    //extension WAVE Elements
    EID_TX_POWER,
    EID_2D_LOCAT = 5,
    EID_3D_LOCAT,
    EID_ADV_ID,
    EID_PSC,
    EID_IPV6ADDR,
    EID_SERVPORT = 10,
    EID_PROV_MAC,
    EID_EDCA_PARAM,
    EID_SEC_DNS,
    EID_GT_MAC,
    EID_CHAN_NUM = 15,
    EID_DATARATE,
    EID_REP_RATE,
    EID_CTRY_STR,
    EID_RCPI_THR,
    EID_WSAC_THR = 20,
    EID_CHAN_ACC,
    EID_INTV_THR = 22,
    // 23 to 127 reserved
    // WSMP WAVE Elements
    EID_WSMP = 128,
    EID_WSMP_S,
    EID_WSMP_ID_SUPP = 130,
    // 131 to 255 reserved
}eid;
static inline unsigned char
calcu_psid_length(unsigned char *psid)
{
    unsigned int num = 0;
    unsigned char first = ~(*psid);
    if(first == 0)
        return 255;

    while(num < 8){
        if(first & 0x80)
            break;
        first = first << 1;
        num += 1;
    }

    return num + 1;
}

static inline u32 psidn2h(char *psid, unsigned int len){
    int i = 0;
    u32 num = 0;
    for(i = 0; i < len; i++){
        num += (*psid)*256;
        psid++;
    }
    return num;
}
static int locate_header_ext(char *wsa, u32 *shift, unsigned int length,
        struct wsa_header_ext *head_ext);

static int locate_serv_ch_info_wra(char *wsa, u32 current_shift, unsigned int length,
        struct service_info *serv_info, struct channel_info *ch_info, struct wra *routing_adv);

static int extract_service_info(string *wsa, 
        struct dot2_service_info_array *ser_infos);

void dot2_service_info_array_free(struct dot2_service_info_array *ptr);
#endif 
