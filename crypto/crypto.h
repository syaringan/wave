/*******
 *
 *这里主要是对二哥写的一些接口进行再一次的包装，使得更符合整个程序内部的规律。
 *
 */
#ifndef CRYPTO_H
#define CRYPTO_H
#include"string.h"
#include"../utils/common.h"
extern int ECDSA256_get_privatekey(char* privatekey_buf, int len);

extern int ECDSA256_get_publickey(char* public_key_x_buf,int xlen, char* public_key_y_buf,int ylen,
				char* private_key_buf, int prilen);

extern int ECDSA256_sign_message(char* private_key_buf,int prilen,  char* mess_buf, int mess_len,
				char* signed_mess_buf, int signed_mess_len);

extern int ECDSA256_verify_messagge(char* public_key_x_buf, int xlen,char* public_key_y_buf,int ylen,
				 char* signed_mess_buf, int signed_mess_len, char* mess_buf, int mess_len);

extern int ECDSA224_get_privatekey(char* privatekey_buf, int len);

extern int ECDSA224_get_publickey(char* public_key_x_buf, int xlen, char* public_key_y_buf,int ylen,
				char* private_key_buf, int prilen);

extern int ECDSA224_sign_message(char* private_key_buf, int prilen , char* mess_buf, int mess_len,
				char* signed_mess_buf, int signed_mess_len);

extern int ECDSA224_verify_messagge(char* public_key_x_buf, int xlen, char* public_key_y_buf, int ylen,
				 char* signed_mess_buf, int signed_mess_len, char* mess_buf, int mess_len);

extern int ECIES256_get_private_key(char* private_key_buf, int prlen);

extern int ECIES256_get_public_key(char* public_key_x_buf, int xlen, char* public_key_y_buf, int ylen, char* private_key_buf, int prilen);

extern int ECIES256_encrypto_message(char* mess_buf, int mess_len, 
			char* encrypto_mess_buf, int encrypto_mess_len, char* public_key_x_buf,int xlen, 
			char* public_key_y_buf, int ylen);


extern int ECIES256_decrypto_message(char* encrypto_mess_buf, int encrypto_mess_len,
			char* decrypto_mess_buf, int decrypto_mess_len, char* private_key_buf, int prilen);

extern int ECIES224_get_private_key(char* private_key_buf, int prlen);

extern int ECIES224_get_public_key(char* public_key_x_buf, int xlen, char* public_key_y_buf, int ylen, char* private_key_buf, int prilen);

extern int ECIES224_encrypto_message(char* mess_buf, int mess_len, 
			char* encrypto_mess_buf, int encrypto_mess_len, char* public_key_x_buf,int xlen, 
			char* public_key_y_buf, int ylen);

extern int ECIES224_decrypto_message(char* encrypto_mess_buf, int encrypto_mess_len,
			char* decrypto_mess_buf, int decrypto_mess_len, char* private_key_buf, int prilen);

extern int HASH256_message(char* message, int len , char* hash_message,
				int hash_len);

extern int HASH224_message(char* message, int len, char* hash_message,
				int hash_len);

inline int crypto_ECDSA256_get_privatekey(string* privatekey){
    if(privatekey == NULL || privatekey->buf != NULL){
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
        res = ECDSA256_get_privatekey(buf,len);
        if(res == 0)
            goto fail;
        len = len*2;
    }while(res == -1);
    
    privatekey->buf = (u8*)malloc(res);
    if( privatekey->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    privatekey->len = res;
    memcpy(privatekey->buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;
}
inline int crypto_ECDSA224_get_privatekey(string* privatekey){
    if(privatekey == NULL || privatekey->buf != NULL){
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
        res = ECDSA224_get_privatekey(buf,len);
        if(res == 0)
            goto fail;
        len = len*2;
    }while(res == -1);
    
    privatekey->buf = (u8*)malloc(res);
    if( privatekey->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    privatekey->len = res;
    memcpy(privatekey->buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;
}

inline int crypto_ECDSA256_get_publickey(string* privatekey,string* public_x_key,string* public_y_key){
    if(public_x_key == NULL || public_y_key == NULL || privatekey == NULL){
        wave_error_printf("输入的参数有问题");
        return -1;
    }
    if(public_x_key->buf != NULL || public_y_key->buf != NULL || privatekey->buf != NULL){
        wave_error_printf("存在野指针");
        return -1;
    }

    char *public_x_buf=NULL,*public_y_buf=NULL;
    int len,res;
    do{
        if(public_x_buf != NULL)
            free(public_x_buf);
        if(public_y_buf != NULL)
            free(public_y_buf);
        public_x_buf = (char*)malloc(len);
        public_y_buf = (char*)malloc(len);
        if(public_x_buf == NULL || public_y_buf == NULL){
            wave_malloc_error();
            goto fail;
        }
        res = ECDSA256_get_publickey(public_x_buf,len,public_y_buf,len,privatekey->buf,privatekey->len);
        if(res == 0)
            goto fail;
        len = len*2;
    }while(res == -1);
    public_x_key->buf = (u8*)malloc(res);
    public_y_key->buf = (u8*)malloc(res);
    if(public_x_key->buf == NULL || public_y_key->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    memcpy(public_x_key->buf,public_x_buf,res);
    memcpy(public_y_key->buf,public_y_buf,res);
    
    free(public_x_buf);
    free(public_y_buf);
    return 0;
fail:
    if(public_x_buf != NULL)
        free(public_x_buf);
    if(public_y_buf != NULL)
        free(public_y_buf);
    if(public_x_key->buf != NULL)
        free(public_x_key->buf);
    if(public_y_key->buf != NULL)
        free(public_y_key->buf);
    return -1;

}
inline int crypto_ECDSA224_get_publickey(string* privatekey,string* public_x_key,string* public_y_key){
    if(public_x_key == NULL || public_y_key == NULL || privatekey == NULL){
        wave_error_printf("输入的参数有问题");
        return -1;
    }
    if(public_x_key->buf != NULL || public_y_key->buf != NULL || privatekey->buf != NULL){
        wave_error_printf("存在野指针");
        return -1;
    }

    char *public_x_buf=NULL,*public_y_buf=NULL;
    int len,res;
    do{
        if(public_x_buf != NULL)
            free(public_x_buf);
        if(public_y_buf != NULL)
            free(public_y_buf);
        public_x_buf = (char*)malloc(len);
        public_y_buf = (char*)malloc(len);
        if(public_x_buf == NULL || public_y_buf == NULL){
            wave_malloc_error();
            goto fail;
        }
        res = ECDSA224_get_publickey(public_x_buf,len,public_y_buf,len,privatekey->buf,privatekey->len);
        if(res == 0)
            goto fail;
        len = len*2;
    }while(res == -1);
    public_x_key->buf = (u8*)malloc(res);
    public_y_key->buf = (u8*)malloc(res);
    if(public_x_key->buf == NULL || public_y_key->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    memcpy(public_x_key->buf,public_x_buf,res);
    memcpy(public_y_key->buf,public_y_buf,res);
    
    free(public_x_buf);
    free(public_y_buf);
    return 0;
fail:
    if(public_x_buf != NULL)
        free(public_x_buf);
    if(public_y_buf != NULL)
        free(public_y_buf);
    if(public_x_key->buf != NULL)
        free(public_x_key->buf);
    if(public_y_key->buf != NULL)
        free(public_y_key->buf);
    return -1;
}
inline int crypto_ECDSA256_sign_message(string* message,string* privatekey,string* signed_message){
    if(message == NULL || privatekey == NULL || signed_message == NULL){
        wave_error_printf("输入参数有问题");
        return -1;
    }
    if(message->buf != NULL || privatekey != NULL || signed_message != NULL){
        wave_error_printf("存在野指针");
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
        res = ECDSA256_sign_message(privatekey->buf,privatekey->len,message->buf,message->len,buf,len);
        if(res == 0)
            goto fail;
        len = len*2;
    }while(res == -1);

    signed_message->buf = (u8*)malloc(res);
    if( signed_message->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    signed_message->len = res;
    memcpy(signed_message->buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;   

}
inline int crypto_ECDSA224_sign_message(string* message,string* privatekey,string* signed_message){
    if(message == NULL || privatekey == NULL || signed_message == NULL){
        wave_error_printf("输入参数有问题");
        return -1;
    }
    if(message->buf != NULL || privatekey != NULL || signed_message != NULL){
        wave_error_printf("存在野指针");
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
        res = ECDSA224_sign_message(privatekey->buf,privatekey->len,message->buf,message->len,buf,len);
        if(res == 0)
            goto fail;
        len = len*2;
    }while(res == -1);

    signed_message->buf = (u8*)malloc(res);
    if( signed_message->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    signed_message->len = res;
    memcpy(signed_message->buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;   

}
inline int crypto_ECDSA256_verify_message(string* public_x_key,string* public_y_key,string* signed_message,
        string* message){
    if(public_x_key == NULL || public_y_key == NULL || signed_message == NULL 
            || message == NULL){
        wave_error_printf("参数有问题");
        return -1;
    }
    
    return ECDSA256_verify_message(public_x_key->buf,public_x_key->len,public_y_key->buf,public_y_key->len,signed_message->buf,signed_message->len,
            message->buf,message->len);
}
inline int crypto_ECDSA224_verify_message(string* public_x_key,string* public_y_key,string* signed_message,
        string* message){
    if(public_x_key == NULL || public_y_key == NULL || signed_message == NULL 
            || message == NULL){
        wave_error_printf("参数有问题");
        return -1;
    }
    
    return ECDSA224_verify_message(public_x_key->buf,public_x_key->len,public_y_key->buf,public_y_key->len,signed_message->buf,signed_message->len,
            message->buf,message->len);
}
inline int crypto_ECIES256_get_private_key(string* privatekey){
    if(privatekey == NULL || privatekey->buf != NULL){
        wave_error_printf("参数有问题");
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
        res = ECIES256_get_private_key(buf,len);
        if(res == 0)
            goto fail;
        len = len*2;
    }while(res == -1);
    
    privatekey->buf = (u8*)malloc(res);
    if( privatekey->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    privatekey->len = res;
    memcpy(privatekey->buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;

}

inline int crypto_ECIES224_get_private_key(string* privatekey){
    if(privatekey == NULL || privatekey->buf != NULL){
        wave_error_printf("参数有问题");
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
        res = ECIES224_get_private_key(buf,len);
        if(res == 0)
            goto fail;
        len = len*2;
    }while(res == -1);
    
    privatekey->buf = (u8*)malloc(res);
    if( privatekey->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    privatekey->len = res;
    memcpy(privatekey->buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;

}
inline int crypto_ECIES256_get_publickey(string* privatekey,string* public_x_key,string* public_y_key){
    if(public_x_key == NULL || public_y_key == NULL || privatekey == NULL){
        wave_error_printf("输入的参数有问题");
        return -1;
    }
    if(public_x_key->buf != NULL || public_y_key->buf != NULL || privatekey->buf != NULL){
        wave_error_printf("存在野指针");
        return -1;
    }

    char *public_x_buf=NULL,*public_y_buf=NULL;
    int len,res;
    do{
        if(public_x_buf != NULL)
            free(public_x_buf);
        if(public_y_buf != NULL)
            free(public_y_buf);
        public_x_buf = (char*)malloc(len);
        public_y_buf = (char*)malloc(len);
        if(public_x_buf == NULL || public_y_buf == NULL){
            wave_malloc_error();
            goto fail;
        }
        res = ECIES256_get_publickey(public_x_buf,len,public_y_buf,len,privatekey->buf,privatekey->len);
        if(res == 0)
            goto fail;
        len = len*2;
    }while(res == -1);
    public_x_key->buf = (u8*)malloc(res);
    public_y_key->buf = (u8*)malloc(res);
    if(public_x_key->buf == NULL || public_y_key->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    memcpy(public_x_key->buf,public_x_buf,res);
    memcpy(public_y_key->buf,public_y_buf,res);
    
    free(public_x_buf);
    free(public_y_buf);
    return 0;
fail:
    if(public_x_buf != NULL)
        free(public_x_buf);
    if(public_y_buf != NULL)
        free(public_y_buf);
    if(public_x_key->buf != NULL)
        free(public_x_key->buf);
    if(public_y_key->buf != NULL)
        free(public_y_key->buf);
    return -1;
}
inline int crypto_ECIES224_get_publickey(string* privatekey,string* public_x_key,string* public_y_key){
    if(public_x_key == NULL || public_y_key == NULL || privatekey == NULL){
        wave_error_printf("输入的参数有问题");
        return -1;
    }
    if(public_x_key->buf != NULL || public_y_key->buf != NULL || privatekey->buf != NULL){
        wave_error_printf("存在野指针");
        return -1;
    }

    char *public_x_buf=NULL,*public_y_buf=NULL;
    int len,res;
    do{
        if(public_x_buf != NULL)
            free(public_x_buf);
        if(public_y_buf != NULL)
            free(public_y_buf);
        public_x_buf = (char*)malloc(len);
        public_y_buf = (char*)malloc(len);
        if(public_x_buf == NULL || public_y_buf == NULL){
            wave_malloc_error();
            goto fail;
        }
        res = ECIES224_get_publickey(public_x_buf,len,public_y_buf,len,privatekey->buf,privatekey->len);
        if(res == 0)
            goto fail;
        len = len*2;
    }while(res == -1);
    public_x_key->buf = (u8*)malloc(res);
    public_y_key->buf = (u8*)malloc(res);
    if(public_x_key->buf == NULL || public_y_key->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    memcpy(public_x_key->buf,public_x_buf,res);
    memcpy(public_y_key->buf,public_y_buf,res);
    
    free(public_x_buf);
    free(public_y_buf);
    return 0;
fail:
    if(public_x_buf != NULL)
        free(public_x_buf);
    if(public_y_buf != NULL)
        free(public_y_buf);
    if(public_x_key->buf != NULL)
        free(public_x_key->buf);
    if(public_y_key->buf != NULL)
        free(public_y_key->buf);
    return -1;
}

inline int crypto_ECIES256_encrypto_message(string* message,string* encryptoed_message,string* public_x_key,string* public_y_key){
    if(message == NULL || encryptoed_message == NULL|| encryptoed_message->buf != NULL 
                 || public_x_key == NULL || public_y_key == NULL){
        wave_error_printf("输入参数有问题");
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
        res = ECIES256_encrypto_message(message->buf,message->len,buf,len,public_x_key->buf,public_x_key->len,public_y_key->buf,public_y_key->len);
        if(res == 0)
            goto fail; 
        len = len*2;
    }while(res == -1);

    encryptoed_message->buf = (u8*)malloc(res);
    if( encryptoed_message->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    encryptoed_message->len = res;
    memcpy(encryptoed_message->buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;   
}

inline int crypto_ECIES224_encrypto_message(string* message,string* encryptoed_message,string* public_x_key,string* public_y_key){
    if(message == NULL || encryptoed_message == NULL|| encryptoed_message->buf != NULL 
                 || public_x_key == NULL || public_y_key == NULL){
        wave_error_printf("输入参数有问题");
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
        res = ECIES224_encrypto_message(message->buf,message->len,buf,len,public_x_key->buf,public_x_key->len,public_y_key->buf,public_y_key->len);
        if(res == 0)
            goto fail; 
        len = len*2;
    }while(res == -1);

    encryptoed_message->buf = (u8*)malloc(res);
    if( encryptoed_message->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    encryptoed_message->len = res;
    memcpy(encryptoed_message->buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;   
}

inline int crypto_ECIES256_decrypto_message(string* encryptoed_message,string* message,string* privatekey){
     if(message == NULL || encryptoed_message == NULL ||message->buf != NULL || privatekey ==  NULL){
        wave_error_printf("输入参数有问题");
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
        res = ECIES256_decrypto_message(encryptoed_message->buf,encryptoed_message->len,message->buf,message->len,
                privatekey->buf,privatekey->len);
        if(res == 0)
            goto fail; 
        len = len*2;
    }while(res == -1);

    message->buf = (u8*)malloc(res);
    if( message->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    message->len = res;
    memcpy(message->buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;   
}
inline int crypto_ECIES224_decrypto_message(string* encryptoed_message,string* message,string* privatekey){
     if(message == NULL || encryptoed_message == NULL ||message->buf != NULL || privatekey ==  NULL){
        wave_error_printf("输入参数有问题");
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
        res = ECIES224_decrypto_message(encryptoed_message->buf,encryptoed_message->len,message->buf,message->len,
                privatekey->buf,privatekey->len);
        if(res == 0)
            goto fail; 
        len = len*2;
    }while(res == -1);

    message->buf = (u8*)malloc(res);
    if( message->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    message->len = res;
    memcpy(message->buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;   
}
inline int crypto_HASH256(string* message,string* hashed_message){
    if(message == NULL || hashed_message == NULL){
        wave_error_printf("输入参数有问题");
        return -1;
    }
    if(message->buf == NULL || hashed_message != NULL ){
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
        res = HASH256_message(message->buf,message->len,buf,len);
        if(res == 0)
            goto fail; 
        len = len*2;
    }while(res == -1);

    hashed_message->buf = (u8*)malloc(res);
    if( hashed_message->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    hashed_message->len = res;
    memcpy(hashed_message->buf,buf,res);
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
    if(message->buf == NULL || hashed_message != NULL ){
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
        res = HASH224_message(message->buf,message->len,buf,len);
        if(res == 0)
            goto fail;
        len = len*2;
    }while(res == -1);

    hashed_message->buf = (u8*)malloc(res);
    if( hashed_message->buf == NULL){
        wave_malloc_error();
        goto fail;
    }
    hashed_message->len = res;
    memcpy(hashed_message->buf,buf,res);
    free(buf);
    return 0;
fail:
    if(buf != NULL)
        free(buf);
    return -1;   
}
#endif
