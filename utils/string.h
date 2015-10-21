#ifndef STRING_H
#define STRING_H
#include "common.h"
#include "stdlib.h"
#include "debug.h"
#include <string.h>
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
        wave_error_printf("string_cpy 内存分配失败,这个是没有在外面检查错误的，错了很可能逻辑要混乱");
        dst->len = 0;
        return;
    }
    memcpy(dst->buf,src->buf,dst->len);
}
/**
 *
 * 如果前部分都相同，断的更小
 */
static inline int string_cmp(string* a,string *b){
    int len,i;
    len = a->len > b->len?b->len:a->len;
    if(a->buf == NULL || b->buf ==NULL){
        wave_error_printf("string cmp 比较的两个string不能有一个为空");
        return -2;
    }
    for(i=0;i< len;i++){
        if(a->buf[i] < b->buf[i])
            return -1;
        if(a->buf[i] > b->buf[i])
            return 1;
    }
    if(len < a->len)
        return 1;
    if( len < b->len)
        return -1;
    return 0;
}
#endif /*STRING_H*/
