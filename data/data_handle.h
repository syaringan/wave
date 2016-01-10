#ifndef DATA_HANDLE_H
#define DATA_HANDLE_H
#include "data.h"
#include "utils/string.h"
//定义三种返回的状态.
#define NOT_ENOUGHT  -2
/**
 * 将sec_data编码成字节流，放到buf里面去。
 * @sec_data : 需要编码的数据结构体。
 * @buf :需要填充的buf。
 * @len：上述buf所拥有的长度，单位字节。
 * return :成功返回填充了多少字节，如果是buf分配的空间不够，返回NOT_ENOUGHT
 *          其他错误,返回FAILURE；
 */

u32 sec_data_2_buf(sec_data* sec_data, u8* buf, u32 len);

/**
 * 将buf里面的字节流，转化成一个sec_data结构体,对于这个结构体指针，这个
 *  接口可以认为这个指针已经指向了一个分配好的内存。
 * @buf:装有字节流的buf。
 * @len:字节流的长度.
 * @sec:需要填充的数据结构，我们可以认为这个指针的内存已经分配好了。
 * return:返回成功或失败。
 */
u32 buf_2_sec_data(u8* buf,u32 len, sec_data* sec);
u32 buf_2_certificate(u8* buf,u32 len,certificate* cert);
/**
 *释放该数据结构内部的指针
 */
void sec_data_free(sec_data* sec_data);
void signed_data_free(signed_data* signed_data,content_type type);
void crl_free(crl* crl);
void certificate_free(certificate* cert);
void certificate_request_free(certificate_request* cert_request);
void encrypted_data_free(encrypted_data* data);
void tobe_encrypted_certificate_response_free(tobe_encrypted_certificate_response* data);
void tobe_encrypted_free(tobe_encrypted* ptr);
void elliptic_curve_point_free(elliptic_curve_point* ptr);
/******************这后面请在data_helper.c里面实现******************/
int sec_data_2_string(sec_data* sec_data,string* data);
int string_2_sec_data(string* data,sec_data* sec_data);

int encrypted_data_2_string(encrypted_data* enc_data,string* data);
int string_2_encrypted_data(string* data,encrypted_data* enc_data);

int certificate_2_string(certificate* cert,string* data);
int string_2_certificate(string* data,certificate* cert);

int signed_data_2_string(signed_data* s_data,string* data);
int string_2_signed_data(string* data,signed_data* s_data);

int crl_2_string(crl *crl,string* data);
int string_2_crl(string* data,crl *crl);

int hashedid8_2_string(hashedid8* hashed,string* data);
int string_2_hashedid8(string* data,hashedid8* hashed);
bool hashedid8_equal(hashedid8* a,hashedid8* b);
void hashedid8_cpy(hashedid8* dst,hashedid8* src);
int  hashedid8_cmp(hashedid8* a,hashedid8* b);

int tobesigned_crl_2_string(tobesigned_crl* tbs_crl,string* data);
int string_2_tobesigned_crl(string* data,tobesigned_crl* tbs_crl);

int certificate_cpy(certificate *dst,certificate *src);
bool certificate_equal(certificate* a,certificate* b);

int elliptic_curve_point_cpy(elliptic_curve_point* dst,elliptic_curve_point* src);

int public_key_cpy(public_key* dst,public_key* src);

int tbsdata_extension_cpy(tbsdata_extension* dst,tbsdata_extension* src);

int tobesigned_wsa_cpy(tobesigned_wsa *dst, tobesigned_wsa *src);

int signed_wsa_2_string(signed_wsa* sw,string* data);
int string_2_signed_wsa(string* data,signed_wsa* sw);
int signed_wsa_cpy(signed_wsa *dst, signed_wsa *src);

int tobesigned_certificate_request_2_string(tobesigned_certificate_request* tbs,string* data);

int string_2_tobe_encrypted_certificate_request_error(string* data,tobe_encrypted_certificate_request_error* cert_requ);

int string_2_tobe_encrypted_certificate_response(string* data,tobe_encrypted_certificate_response* cert_resp);

int certificate_request_2_string(certificate_request* cert_req,string* data);

int tobe_encrypted_2_string(tobe_encrypted* tbencrypted,string* data);
int string_2_tobe_encrypted(string *data,tobe_encrypted* tbencrypted);

int tobesigned_certificate_2_string(tobesigned_certificate* cert,string* data,u8 verision_and_type);
int tobesigned_wsa_2_string(tobesigned_wsa* wsa,string* data);
int tobesigned_data_2_string(tobesigned_data* tbsigneddata,string* data);
bool certid10_equal(certid10* a,certid10* b);
int  certid10_cmp(certid10 *a,certid10* b);
void certid10_cpy(certid10* dst,certid10* src);

void geographic_region_cpy(geographic_region* dst,geographic_region* src);
/**************证书打印，在data_printf.c中实现******************/
static void space_print(int n);

void two_d_location_printf(two_d_location* two_d_location,int n);
void rectangular_region_printf(rectangular_region* rectangular_region,int n);
void circular_region_printf(circular_region* circular_region,int n);

void geographic_region_printf(geographic_region* geographic_region,int n);
void psid_priority_printf(psid_priority* psid_priority,int n);
void psid_priority_array_printf(psid_priority_array* psid_pa,int n);
void psid_array_printf(psid_array* psid_array,int n);
void psid_ssp_printf(psid_ssp* psid_ssp,int n);
void psid_ssp_array_printf(psid_ssp_array* psid_ssp_array,int n);
void psid_priority_ssp_printf(psid_priority_ssp* psid_ps,int n);
void psid_priority_ssp_array_printf(psid_priority_ssp_array* psid_psa,int n);

void root_ca_scope_printf(root_ca_scope* root_ca_scope,int n);
void sec_data_exch_ca_scope_printf(sec_data_exch_ca_scope* sec_decs,int n);
void wsa_ca_scope_printf(wsa_ca_scope* wsa_cs,int n);
void identified_not_localized_scope_printf(identified_not_localized_scope* id_nls,int n);
void identified_scope_printf(identified_scope* identified_scope,int n);
void anonymous_scope_printf(anonymous_scope* anonymous_scope,int n);
void wsa_scope_printf(wsa_scope* wsa_scope,int n);
void cert_specific_data_printf(cert_specific_data* cert_sd,int n,holder_type holder_type);
void public_key_printf(public_key* public_key,int n);
void ecdsa_signature_printf(ecdsa_signature* ecdsa_sig,int n);
void tobesigned_certificate_printf(tobesigned_certificate* tbs_cert,int n,char version_and_type);
void signature_printf(signature* signature,int n,pk_algorithm algorithm);
void elliptic_curve_point_printf(elliptic_curve_point* ell_cp,int n);
void certificate_printf(certificate* cert);
#endif
