/*******
 *
 *这里主要是对二哥写的一些接口进行再一次的包装，使得更符合整个程序内部的规律。
 *
 */
#ifndef CRYPTO_H
#define CRYPTO_H
#include"crypto_interface.h"
#include"string.h"
#include"common.h"

inline int crypto_ECDSA_get_privatekey(string* privatekey){
    if(privatekey == NULL || privatekey.buf != NULL){
        wave_error_printf("输入参数有错误，请检查");
        return -1;
    }
    int res;
    char *buf=NULL;
    int len = 1024;
    do{
        if(buf != NULL)
            free(buf);
        buf = (char*)malloc(len);
        if(buf == NULL){
            wave_malloc_error();
            goto fail;
        }
        res = ECDSA_get_privatekey(buf,len);
        len = len*2;
    }while(res == -1);
    
    privatekey.buf = (u8*)malloc(res);
    if( privatekey.buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    privatekey.len = res;
    memcpy(privatekey.buf,buf,res);
    free(buff);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;
}

inline int crypto_ECDSA_get_publickey(string* public_x_key,string* public_y_key,string* privatekey ){
    if(public_x_key == NULL || public_y_key == NULL || privatekey == NULL){
        wave_error_printf("输入的参数有问题");
        return -1;
    }
    if(public_x_key.buf != NULL || public_y_key.buf != NULL || privatekey.buf != NULL){
        wave_error_printf("存在野指针");
        return -1;
    }

    char *public_x_buf,*public_y_buf,*private_buf;

}

inline int crypto_HASH256(string* message,string* hashed_message){
    if(message == NULL || hashed_message == NULL){
        wave_error_printf("输入参数有问题");
        return -1;
    }
    if(message.buf == NULL || hashed_message != NULL ){
        wave_error_printf("输入string里面buf有问题");
        return -1;
    }
    char* buf = NULL;
    int len = 1024,res;
    do{
        if(buf != NULL)
            free(buf);
        buf = (char*)malloc(len);
        if(buf == NULL){
            wave_malloc_error();
            goto fail;
        }
        res = HASH256_message(message.buf,message.len,buf,len);
        len = len*2;
    }while(res == -1);

    hashed_message.buf = (u8*)malloc(res);
    if( hashed_message.buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    hashed_message.len = res;
    memcpy(hashed_message.buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;   
}
inline int crypto_HASH224(string* message,string* hashed_message){
    if(message == NULL || hashed_message == NULL){
        wave_error_printf("输入参数有问题");
        return -1;
    }
    if(message.buf == NULL || hashed_message != NULL ){
        wave_error_printf("输入string里面buf有问题");
        return -1;
    }
    char* buf = NULL;
    int len = 1024,res;
    do{
        if(buf != NULL)
            free(buf);
        buf = (char*)malloc(len);
        if(buf == NULL){
            wave_malloc_error();
            goto fail;
        }
        res = HASH224_message(message.buf,message.len,buf,len);
        len = len*2;
    }while(res == -1);

    hashed_message.buf = (u8*)malloc(res);
    if( hashed_message.buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    hashed_message.len = res;
    memcpy(hashed_message.buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;   
}
#endif
