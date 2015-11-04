#ifndef DATA_HANDLE_H
#define DATA_HANDLE_H
#include "data.h"
#include "../utils/string.h"
//定义三种返回的状态.
u32 NOT_ENOUGHT = -2;
/**
 * 将sec_data编码成字节流，放到buf里面去。
 * @sec_data : 需要编码的数据结构体。
 * @buf :需要填充的buf。
 * @len：上述buf所拥有的长度，单位字节。
 * return :成功返回填充了多少字节，如果是buf分配的空间不够，返回NOT_ENOUGHT
 *          其他错误,返回FAILURE；
 */

u32 sec_data_2_buf(const sec_data* sec_data, u8* buf, u32 len);

/**
 * 将buf里面的字节流，转化成一个sec_data结构体,对于这个结构体指针，这个
 *  接口可以认为这个指针已经指向了一个分配好的内存。
 * @buf:装有字节流的buf。
 * @len:字节流的长度.
 * @sec:需要填充的数据结构，我们可以认为这个指针的内存已经分配好了。
 * return:返回成功或失败。
 */
u32 buf_2_sec_data(const u8* buf,u32 len, sec_data* sec);

/**
 *释放该数据结构内部的指针
 */
void sec_data_free(sec_data* sec_data);
void signed_data_free(signed_data* signed_data);
void crl_free(crl* crl);
void certificate_request_free(certificate_request* cert_request);

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

int tobesigned_crl_2_string(tobesigned_crl* tbs_crl,string* data);
int string_2_tobesigned_crl(string* data,tobesigned_crl* tbs_crl);

int certificate_cpy(certificate *dst,certificate *src);

bool certificate_equal(certificate* a,certificate* b);

int elliptic_curve_point_cpy(elliptic_curve_point* src,elliptic_curve_point* dst);

int public_key_cpy(public_key* a,public_key* b);

int tobesigned_certificate_request_2_string(tobesigned_certificate_request* tbs,string* data);
int certificate_request_2_string(certificate_request* cert_req,string* data);
#endif
