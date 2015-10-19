#ifndef STRING_H
#define STRING_H
#include "common.h"
#include "stdlib.h"
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
#endif /*STRING_H*/
