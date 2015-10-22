#ifndef DATA_HANDLE_H
#define DATA_HANDLE_H
#include "data.h"
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
 * 释放这个sec_data，这里要递归的去释放。
 */
void sec_data_free(sec_data* sec_data);

/**
 * 证书的复制
 */
void certificate_cpy(certificate *dst,certificate *src);

bool certificate_equal(certificate* a,certificate* b);

#endif
