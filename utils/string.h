#ifndef STRING_H
#define STRING_H
#include "common.h"
#include "stdlib.h"
#include "debug.h"
typedef struct string{
    u8 *buf;
    u16 len;
}string;
/**
 * 释放一个string的指针
 */
static inline void string_free(string *str){
    if(str->buf == NULL)
        return;
    free(str->buf);
    str->buf = NULL;
    str->len = 0;
}
static inline void string_cpy(string* dst,string* src){
    if(dst->buf != NULL){
        wave_error_printf("string_cpy dst的buf必须为NULL");
        return;
    }
    dst->len = src->len;
    dst->buf = (u8*)malloc(dst->len);
    if(dst->buf == NULL){
        wave_error_printf("string_cpy 内存分配失败");
        dst->len = 0;
        return;
    }
    memcpy(dst->buf,src->buf,dst->len);
}
#endif /*STRING_H*/
