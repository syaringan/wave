/*=============================================================================
#
# Author: 杨广华 - edesale@qq.com
#
# QQ : 374970456
#
# Last modified: 2015-10-19 14:46
#
# Filename: crypto.c
#
# Description:测试程序，用于检测c++加密算法接口是否正常使用
#
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>



extern int ECDSA_224_get_key( char* privatekey_buf, int* prlen, char* public_key_x_buf, int* xlen, char* public_key_y_buf, int* ylen );


extern int ECDSA_224_uncompress_key_2_compress_key(char *public_key_x, int public_key_x_len,
                                            char *public_key_y, int public_key_y_len,
                                            char *compress_key, int *compress_key_len,
                                            char *flag);


extern int ECDSA_224_compress_key_2_uncompress(char *compress_key, int compress_key_len,
                                        char old_flag,

                                        char *public_key_x_buf, int *public_key_x_len,
                                        char *public_key_y_buf, int *public_key_y_len);


extern int ECDSA_224_sign_message(char* private_key_buf, int prilen,
                           char* mess_buf, int mess_len,

			                char* r,int *r_len, 
                            char* s,int *s_len);


extern int ECDSA_224_verify_message(char* public_key_x_buf, int xlen,
                             char* public_key_y_buf, int ylen,
                             char* r,int r_len,
                             char* s,int s_len,
                             char* mess_buf, int mess_len);


extern int ECDSA_224_FAST_sign_message(char* private_key_buf, int prilen,
                                char* mess_buf, int mess_len,

                                char* signed_R_x, int* signed_R_x_len,
                                char* signed_R_y, int* signed_R_y_len,
                                char* signed_S, int* signed_S_len);


extern int ECDSA_224_FAST_verify_message(char* public_key_x_buf, int xlen,
                                  char* public_key_y_buf, int ylen,
                                  char* mess_buf, int mess_len,
                                  char* signed_R_x, int signed_R_x_len,
                                  char* signed_R_y, int signed_R_y_len,
                                  char* signed_S, int signed_S_len);


extern int ECDSA_256_get_key( char* privatekey_buf, int* prlen, char* public_key_x_buf, int* xlen, char* public_key_y_buf, int* ylen);

extern int ECDSA_256_uncompress_key_2_compress_key(char *public_key_x, int public_key_x_len,
                                            char *public_key_y, int public_key_y_len,
                                            char *compress_key, int *compress_key_len,
                                            char *flag);

extern int ECDSA_256_compress_key_2_uncompress(char *compress_key,int compress_key_len,
                                        char old_flag,

                                        char *public_key_x_buf, int* public_key_x_len,
                                        char *public_key_y_buf, int* public_key_y_len);

extern int ECDSA_256_sign_message(char* private_key_buf, int prilen,
                           char* mess_buf, int mess_len,

                           char* r,int *r_len,
                           char* s,int *s_len);

extern int ECDSA_256_verify_message(char* public_key_x_buf, int xlen,
                             char* public_key_y_buf, int ylen,
                             char* r, int r_len,
                             char* s,  int s_len,
                             char* mess_buf, int mess_len);

extern int ECDSA_256_FAST_sign_message(char* private_key_buf, int prilen,
                                char* mess_buf, int mess_len,
                                char* signed_R_x, int* signed_R_x_len,
                                char* signed_R_y, int* signed_R_y_len,
                                char* signed_S, int* signed_S_len);

extern int ECDSA_256_FAST_verify_message(char* public_key_x_buf, int xlen,
                                  char* public_key_y_buf, int ylen,
                                  char* mess_buf, int mess_len,
                                  char* signed_R_x, int signed_R_x_len,
                                  char* signed_R_y, int signed_R_y_len,
                                  char* signed_S, int signed_S_len);


extern int ECIES_get_key(char* private_key_buf, int* private_klen,
                  char *public_key_x_buf, int* public_key_x_len,
                  char *public_key_y_buf, int* public_key_y_len);


extern int ECIES_uncompress_key_2_compress_key(char *public_key_x, int public_key_x_len,
                                        char *public_key_y, int public_key_y_len,
                                        char *compress_key, int *compress_key_len,
                                        char *flag);


extern int ECIES_compress_key_2_uncompress(char *compress_key,int compress_key_len,
                                    char old_flag,

                                    char *public_key_x_buf, int* public_key_x_len,
                                    char *public_key_y_buf, int* public_key_y_len);


extern int ECIES_encrypto_message(char* mess_buf, int mess_len,
                           char* public_key_x_buf, int xlen,
                           char* public_key_y_buf, int ylen,

                           char* ephe_public_key_x, int *ephe_public_key_x_len,
                           char* ephe_public_key_y, int *ephe_public_key_y_len,
		                   char* encrypto_mess_buf, int *encrypto_mess_len,
                           char* tag, int *tag_len);


extern int ECIES_decrypto_message( char* encrypto_mess_buf, int encrypto_mess_len,
                           char* ephe_public_key_x, int ephe_public_key_x_len,
                           char* ephe_public_key_y, int ephe_public_key_y_len,
                           char* tag,int tag_len,
                           char* private_key_buf, int prilen,

		                    char* decrypto_mess_buf, int* decrypto_mess_len);



extern int AES_128_CCM_Get_Key_and_Nonce(char* sym_key, int *sym_key_len, char* nonce, int* nonce_len);


extern int AES_128_CCM_encrypto_message(char *plaintext, int length_of_plaintext,
                                 char *sym_key, int sym_key_len,
                                 char *nonce, int nonce_len,
                                 char *ciphertext, int *length_of_ciphertext);


extern int AES_128_CCM_decrypto_message(char *ciphertext, int length_of_ciphertext,
                                 const char *sym_key, int sym_key_len,
                                 const char *nonce, int nonce_len,
                                 char *plaintext, int *length_of_plaintext);



extern int sha_256(char* message, int message_len, char* digest, int* digest_len);




int main()
{


/******* ECIEES ********/
/*
char *privatekey;
int private_klen = 32;
char *publickey_x;
int publickey_x_len = 32;
char *publickey_y;
int publickey_y_len = 32;
char *publickey_x1;
int publickey_x1_len = 32;
char *publickey_y1;
int publickey_y1_len = 32;
char *compresskey;
int compresskeylen = 32;
char flag = -1;
char flag1 = -1;

privatekey = (char *)malloc(32*sizeof(char));
publickey_x = (char *)malloc(32*sizeof(char));
publickey_y = (char *)malloc(32*sizeof(char));
publickey_x1 = (char *)malloc(32*sizeof(char));
publickey_y1 = (char *)malloc(32*sizeof(char));
compresskey = (char *)malloc(32*sizeof(char));

int a = ECIES_get_key(privatekey, &private_klen, publickey_x, &publickey_x_len, publickey_y, &publickey_y_len);
if(a!=0)
{
    printf("1 error!!!!!!\n");
    return -1;
}
printf("MAIN!!!!!!!!!*********************11111111 flag is : %d\n", flag);
int uuu = 0;

printf("MAIN!!!!!!!!!!*********************the public_x key is:\n");
for(uuu=0; uuu<32; uuu++)
   printf("%x ",publickey_x[uuu]);
printf("\n");
uuu = 0;
printf("MAIN!!!!!!!!!!*********************the public_y key is:\n");
for(uuu=0; uuu<32; uuu++)
   printf("%x ",publickey_y[uuu]);
printf("\n");

int b = ECIES_uncompress_key_2_compress_key(publickey_x, publickey_x_len, publickey_y, publickey_y_len, compresskey, &compresskeylen, &flag);
if(b!=0)
{
    printf("2 error!!!!!!\n");
    return -1;
}

printf("MAIN!!!!!!!!!*********************22222222 flag is : %d\n", flag);
uuu = 0;
printf("*********************the compress key is:\n");
for(uuu=0; uuu<32; uuu++)
   printf("%x ",compresskey[uuu]);
printf("\n");

int c = ECIES_compress_key_2_uncompress(compresskey, compresskeylen, flag, publickey_x1, &publickey_x1_len, publickey_y1, &publickey_y1_len);
if(c!=0)
{
    printf("3 error!!!!!!\n");
    return -1;
}

printf("MAIN!!!!!!!!!*********************33333333 flag is : %d\n", flag);
uuu = 0;
printf("MAIN!!!!!!!!!!*********************the public_x key is:\n");
for(uuu=0; uuu<32; uuu++)
   printf("%x ",publickey_x1[uuu]);
printf("\n");
uuu = 0;
printf("MAIN!!!!!!!!!!*********************the public_y key is:\n");
for(uuu=0; uuu<32; uuu++)
   printf("%x ",publickey_y1[uuu]);
printf("\n");


char mess[100] = "hello1djkasdjkbnasdjb jdhjkas;";
int mess_len = 30;
char en_mess[200] = {0};
int en_mess_len = 200;

char flagecies = -1;
char* ephe_public_key_x = (char*)malloc(32*sizeof(char));
int ephe_public_key_x_len = 32;
char* ephe_public_key_y = (char*)malloc(32*sizeof(char));
int ephe_public_key_y_len = 32;
char* tag = (char*)malloc(20*sizeof(char));
int tag_len = 20;

int yyy = ECIES_encrypto_message(mess, mess_len, publickey_x1, publickey_x1_len, publickey_y1, publickey_y1_len, ephe_public_key_x, &ephe_public_key_x_len, ephe_public_key_y, &ephe_public_key_y_len, en_mess, &en_mess_len, tag, &tag_len);

printf("ECIES加密数据长度 = %d\n",en_mess_len);
printf("ECIES加密数据为：%s\n", en_mess);


printf("ephe_public_key_x is :\n");
for(uuu=0; uuu<ephe_public_key_x_len; uuu++)
    printf("%x ",ephe_public_key_x[uuu]);
printf("\n");

printf("ephe_public_key_y is :\n");
for(uuu=0; uuu<ephe_public_key_y_len; uuu++)
    printf("%x ",ephe_public_key_y[uuu]);
printf("\n");

printf("en_mess is :\n");
for(uuu=0; uuu<en_mess_len; uuu++)
    printf("%x ",en_mess[uuu]);
printf("\n");

printf("tag_len is %d\n",tag_len);
printf("tag is :\n");
for(uuu=0; uuu<tag_len; uuu++)
    printf("%x ",tag[uuu]);
printf("\n");

char de_mess[200] = {0};
int de_mess_len = 200;



//下面的代码测试差错控制,有差错时系统不能直接崩掉:

char error_en_mess[30] = {'f'};
int error_en_mess_len = 30;

int xxx0 = ECIES_decrypto_message(error_en_mess, error_en_mess_len, ephe_public_key_x, ephe_public_key_x_len, ephe_public_key_y, ephe_public_key_y_len, tag, tag_len, privatekey, private_klen, de_mess, &de_mess_len);

printf("0000ECIES解密数据长度 = %d\n", de_mess_len);
printf("0000ECIES解码数据为：%s\n", de_mess);


char error_tag[20] = {'p'};
int error_tag_len = 20;

int xxx1 = ECIES_decrypto_message(en_mess, en_mess_len, ephe_public_key_x, ephe_public_key_x_len, ephe_public_key_y, ephe_public_key_y_len, error_tag, error_tag_len, privatekey, private_klen, de_mess, &de_mess_len);

printf("0001ECIES解密数据长度 = %d\n", de_mess_len);
printf("0001ECIES解码数据为：%s\n", de_mess);


char error_privatekey[32] = {'l'};
int error_private_klen = 32;

int xxx2 = ECIES_decrypto_message(en_mess, en_mess_len, ephe_public_key_x, ephe_public_key_x_len, ephe_public_key_y, ephe_public_key_y_len, tag, tag_len, error_privatekey, error_private_klen, de_mess, &de_mess_len);

printf("0002ECIES解密数据长度 = %d\n", de_mess_len);
printf("0002ECIES解码数据为：%s\n", de_mess);

//上面的代码测试差错控制,有差错时系统不能直接崩掉.
//差错测试通过!!!!



int xxx = ECIES_decrypto_message(en_mess, en_mess_len, ephe_public_key_x, ephe_public_key_x_len, ephe_public_key_y, ephe_public_key_y_len, tag, tag_len, privatekey, private_klen, de_mess, &de_mess_len);

printf("ECIES解密数据长度 = %d\n", de_mess_len);
printf("ECIES解码数据为：%s\n", de_mess);


free(privatekey);
free(publickey_x);
free(publickey_x1);
free(publickey_y);
free(publickey_y1);
free(compresskey);
*/






/********* ECDSA_224 ************/
/*
char *privatekey;
int private_klen = 100;
char *publickey_x;
int publickey_x_len = 100;
char *publickey_y;
int publickey_y_len = 100;
char *publickey_x1;
int publickey_x1_len = 100;
char *publickey_y1;
int publickey_y1_len = 100;
char *compresskey;
int compresskeylen = 100;
char flag = -1;
char flag1 = -1;


privatekey = (char *)malloc(100*sizeof(char));
publickey_x = (char *)malloc(100*sizeof(char));
publickey_y = (char *)malloc(100*sizeof(char));
publickey_x1 = (char *)malloc(100*sizeof(char));
publickey_y1 = (char *)malloc(100*sizeof(char));
compresskey = (char *)malloc(100*sizeof(char));

int result = ECDSA_224_get_key( privatekey, &private_klen, publickey_x, &publickey_x_len, publickey_y, &publickey_y_len);
int uuu = 0;

printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!the private key is : \n");
for(uuu=0; uuu<private_klen; uuu++)
    printf("%x ",privatekey[uuu]);
printf("\n");

printf("!!!!!!!!!!!!!!!!!!!!!!!!!!the public_key_x is : \n");
for(uuu=0; uuu<publickey_x_len; uuu++)
    printf("%x ",publickey_x[uuu]);
printf("\n");

printf("!!!!!!!!!!!!!!!!!!!!!!!!!the public_key_y is : \n");
for(uuu=0; uuu<publickey_y_len; uuu++)
    printf("%x ",publickey_y[uuu]);
printf("\n");

int b = ECDSA_224_uncompress_key_2_compress_key(publickey_x, publickey_x_len, publickey_y, publickey_y_len, compresskey, &compresskeylen, &flag);

printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!the compress key is : \n");
for(uuu=0; uuu<compresskeylen; uuu++)
    printf("%x ",compresskey[uuu]);
printf("\n");

result = ECDSA_224_compress_key_2_uncompress(compresskey, compresskeylen, flag, publickey_x1, &publickey_x1_len, publickey_y1,               
                                             &publickey_y1_len);

printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!the public_key_x1 is : \n");
for(uuu=0; uuu<publickey_x1_len; uuu++)
    printf("%x ",publickey_x1[uuu]);
printf("\n");

printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!the public_key_y1 is : \n");
for(uuu=0; uuu<publickey_y1_len; uuu++)
    printf("%x ",publickey_y1[uuu]);
printf("\n");

char *mess;
mess = (char *)malloc(100*sizeof(char));
int mess_len = 100;
for(uuu=0; uuu<73; uuu++)
     mess[uuu] = 's';
mess_len = 73;
char *signed_mess_buf;
signed_mess_buf = (char *)malloc(100*sizeof(char));
int signed_mess_len = 100;

char* r = (char*)malloc(100*sizeof(char));
int r_len = 100;
char* s = (char*)malloc(100*sizeof(char));
int s_len = 100;

int sign_result = ECDSA_224_sign_message(privatekey, private_klen, mess, mess_len, r, &r_len, s, &s_len);

printf("the length of signatue is %d\n", signed_mess_len);
printf("the signature is \n");
printf("%s\n", signed_mess_buf);




//下面的代码测试差错控制,有差错时系统不能直接崩掉:

char* error_r = (char*)malloc(28*sizeof(char));
int error_r_len = 28;
for(uuu=0; uuu<28; uuu++)
    error_r[uuu] = 'c';

int veri_result0 = ECDSA_224_verify_message(publickey_x1, publickey_x1_len, publickey_y1, publickey_y1_len, error_r, error_r_len, s, s_len, mess, mess_len);

if( veri_result0 == -1 )
    printf("*******************00000 Verify Failed !!!!!!!!!!!!!!!!!!!\n");
if( veri_result0 == 0 )
    printf("*******************00000 Verify Succeed !!!!!!!!!!!!!!!!!!!\n");

//上面的代码测试差错控制,有差错时系统不能直接崩掉.
//差错测试通过!!!!



int veri_result = ECDSA_224_verify_message(publickey_x1, publickey_x1_len, publickey_y1, publickey_y1_len, r, r_len, s, s_len, mess, mess_len);

if( veri_result == -1 )
    printf("******************* Verify Failed !!!!!!!!!!!!!!!!!!!\n");
if( veri_result == 0 )
    printf("******************* Verify Succeed !!!!!!!!!!!!!!!!!!!\n");

char* signed_R_x;
signed_R_x = (char*)malloc(100*sizeof(char));
int signed_R_x_len = 100;
char* signed_R_y;
signed_R_y = (char*)malloc(100*sizeof(char));
int signed_R_y_len = 100;
char* signed_S;
signed_S = (char*)malloc(100*sizeof(char));
int signed_S_len = 100;

int FAST_sign_result = ECDSA_224_FAST_sign_message(privatekey, private_klen,
                                                   mess, mess_len,
                                                   signed_R_x, &signed_R_x_len,
                                                   signed_R_y, &signed_R_y_len,
                                                   signed_S, &signed_S_len);

printf("FAST_sign_result = %d\n",FAST_sign_result);

printf("signed_R_x_len = %d\n",signed_R_x_len);
printf("~~~~~~~~~~~~~~signed_R_x is: \n");
for(uuu=0; uuu<signed_R_x_len; uuu++)
    printf("%x ",signed_R_x[uuu]);
printf("\n");

printf("signed_R_y_len = %d\n",signed_R_y_len);
printf("~~~~~~~~~~~~~~signed_R_y is: \n");
for(uuu=0; uuu<signed_R_y_len; uuu++)
    printf("%x ",signed_R_y[uuu]);
printf("\n");

printf("signed_S_len = %d\n",signed_S_len);
printf("~~~~~~~~~~~~~~signed_S is: \n");
for(uuu=0; uuu<signed_S_len; uuu++)
    printf("%x ",signed_S[uuu]);
printf("\n");




//下面的代码测试差错控制,有差错时系统不能直接崩掉:

char* error_signed_R_x = (char*)malloc(28*sizeof(char));
int error_signed_R_x_len = 28;
for(uuu=0; uuu<28; uuu++)
    error_signed_R_x[uuu] = 'c';

int FAST_verify_result0 = ECDSA_224_FAST_verify_message(publickey_x1, publickey_x1_len,
                                                       publickey_y1, publickey_y1_len,
                                                       mess, mess_len,
                                                       error_signed_R_x, error_signed_R_x_len,
                                                       signed_R_y, signed_R_y_len,
                                                       signed_S, signed_S_len);
printf("~~~~~~~~~~~~ FAST_verify_result0 is %d\n",FAST_verify_result0);

//上面的代码测试差错控制,有差错时系统不能直接崩掉.
//差错测试通过!!!!




int FAST_verify_result = ECDSA_224_FAST_verify_message(publickey_x1, publickey_x1_len,
                                                       publickey_y1, publickey_y1_len,
                                                       mess, mess_len,
                                                       signed_R_x, signed_R_x_len,
                                                       signed_R_y, signed_R_y_len,
                                                       signed_S, signed_S_len);
printf("~~~~~~~~~~~~ FAST_verify_result is %d\n",FAST_verify_result);
*/






/********* ECDSA_256 ************/
/*
char *privatekey;
int private_klen = 100;
char *publickey_x;
int publickey_x_len = 100;
char *publickey_y;
int publickey_y_len = 100;
char *publickey_x1;
int publickey_x1_len = 100;
char *publickey_y1;
int publickey_y1_len = 100;
char *compresskey;
int compresskeylen = 100;
char flag = -1;
char flag1 = -1;


privatekey = (char *)malloc(100*sizeof(char));
publickey_x = (char *)malloc(100*sizeof(char));
publickey_y = (char *)malloc(100*sizeof(char));
publickey_x1 = (char *)malloc(100*sizeof(char));
publickey_y1 = (char *)malloc(100*sizeof(char));
compresskey = (char *)malloc(100*sizeof(char));

int result = ECDSA_256_get_key( privatekey, &private_klen, publickey_x, &publickey_x_len, publickey_y, &publickey_y_len);
int uuu = 0;

printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!the private key is : \n");
for(uuu=0; uuu<private_klen; uuu++)
    printf("%x ",privatekey[uuu]);
printf("\n");

printf("!!!!!!!!!!!!!!!!!!!!!!!!!!the public_key_x is : \n");
for(uuu=0; uuu<publickey_x_len; uuu++)
    printf("%x ",publickey_x[uuu]);
printf("\n");

printf("!!!!!!!!!!!!!!!!!!!!!!!!!the public_key_y is : \n");
for(uuu=0; uuu<publickey_y_len; uuu++)
    printf("%x ",publickey_y[uuu]);
printf("\n");

int b = ECDSA_256_uncompress_key_2_compress_key(publickey_x, publickey_x_len, publickey_y, publickey_y_len, compresskey, &compresskeylen, &flag);
printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!the compress key is : \n");
for(uuu=0; uuu<compresskeylen; uuu++)
    printf("%x ",compresskey[uuu]);
printf("\n");

result = ECDSA_256_compress_key_2_uncompress(compresskey, compresskeylen, flag, publickey_x1, &publickey_x1_len, publickey_y1, 
                                             &publickey_y1_len);
printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!the public_key_x1 is : \n");
for(uuu=0; uuu<publickey_x1_len; uuu++)
    printf("%x ",publickey_x1[uuu]);
printf("\n");

printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!the public_key_y1 is : \n");
for(uuu=0; uuu<publickey_y1_len; uuu++)
    printf("%x ",publickey_y1[uuu]);
printf("\n");

char *mess;
mess = (char *)malloc(100*sizeof(char));
int mess_len = 100;
for(uuu=0; uuu<73; uuu++)
     mess[uuu] = 's';
mess_len = 73;

char* r = (char*)malloc(100*sizeof(char));
int r_len = 100;
char* s = (char*)malloc(100*sizeof(char));
int s_len = 100;

int sign_result = ECDSA_256_sign_message(privatekey, private_klen, mess, mess_len, r, &r_len, s, &s_len);


//下面的代码测试差错控制,有差错时系统不能直接崩掉:

char* error_r = (char*)malloc(32*sizeof(char));
int error_r_len = 32;
for(uuu=0; uuu<32; uuu++)
    error_r[uuu] = 'c';

int veri_result0 = ECDSA_256_verify_message(publickey_x1, publickey_x1_len, publickey_y1, publickey_y1_len, error_r, error_r_len, s, s_len, mess, mess_len);

if( veri_result0 == -1 )
    printf("*******************00000 Verify Failed !!!!!!!!!!!!!!!!!!!\n");
if( veri_result0 == 0 )
    printf("*******************00000 Verify Succeed !!!!!!!!!!!!!!!!!!!\n");

//上面的代码测试差错控制,有差错时系统不能直接崩掉.
//差错测试通过!!!!



int veri_result = ECDSA_256_verify_message(publickey_x1, publickey_x1_len, publickey_y1, publickey_y1_len,
                                           r, r_len, s, s_len, mess, mess_len);
if( veri_result == -1 )
    printf("******************* Verify Failed !!!!!!!!!!!!!!!!!!!\n");
if( veri_result == 0 )
    printf("******************* Verify Succeed !!!!!!!!!!!!!!!!!!!\n");

char* signed_R_x;
signed_R_x = (char*)malloc(100*sizeof(char));
int signed_R_x_len = 100;
char* signed_R_y;
signed_R_y = (char*)malloc(100*sizeof(char));
int signed_R_y_len = 100;
char* signed_S;
signed_S = (char*)malloc(100*sizeof(char));
int signed_S_len = 100;

int FAST_sign_result = ECDSA_256_FAST_sign_message(privatekey, private_klen,
                                                   mess, mess_len,
                                                   signed_R_x, &signed_R_x_len,
                                                   signed_R_y, &signed_R_y_len,
                                                   signed_S, &signed_S_len);
printf("FAST_sign_result = %d\n",FAST_sign_result);

printf("signed_R_x_len = %d\n",signed_R_x_len);
printf("~~~~~~~~~~~~~~signed_R_x is: \n");
for(uuu=0; uuu<signed_R_x_len; uuu++)
    printf("%x ",signed_R_x[uuu]);
printf("\n");

printf("signed_R_y_len = %d\n",signed_R_y_len);
printf("~~~~~~~~~~~~~~signed_R_y is: \n");
for(uuu=0; uuu<signed_R_y_len; uuu++)
    printf("%x ",signed_R_y[uuu]);
printf("\n");

printf("signed_S_len = %d\n",signed_S_len);
printf("~~~~~~~~~~~~~~signed_S is: \n");
for(uuu=0; uuu<signed_S_len; uuu++)
    printf("%x ",signed_S[uuu]);
printf("\n");

int FAST_verify_result = ECDSA_256_FAST_verify_message(publickey_x1, publickey_x1_len,
                                                       publickey_y1, publickey_y1_len,
                                                       mess, mess_len,
                                                       signed_R_x, signed_R_x_len,
                                                       signed_R_y, signed_R_y_len,
                                                       signed_S, signed_S_len);
printf("~~~~~~~~~~~~ FAST_verify_result is %d\n",FAST_verify_result);
*/





/********* SHA_256 **************/
/*
char *message;
message = (char*)malloc(300*sizeof(char));
int message_len = 700;
int uuu = 0;
for(uuu=0; uuu<300; uuu++)
    message[uuu] = 'a' ;
char *digest;
digest = (char*)malloc(100*sizeof(char));
int digest_len = 100;

int sha256 = sha_256(message, message_len, digest, &digest_len);

printf("the sha256 = %d\n", sha256);
printf("the digest_len is %d\n",digest_len);
printf(" the digest is : \n");
for(uuu=0; uuu<digest_len; uuu++)
    printf("%x ", digest[uuu]);
printf("\n");
*/






/*****************AES_CCM**************/

		printf("*************************AES_CCM************************:\n");

		char shuru[100] = {0};
                int shuru_len = 71;
		int i;
		for(i=0;i<71;i++)
		     shuru[i] = 'a';
        char shuchu[100] = {0};
        int shuchu_len = 100;
        unsigned char key[16] = {0};
        int key_len = 16;
        unsigned char iv[12] = {0};
        int iv_len = 12;

        AES_128_CCM_Get_Key_and_Nonce(key, &key_len, iv, &iv_len);
        AES_128_CCM_encrypto_message(shuru, shuru_len, key, key_len, iv, iv_len, shuchu, &shuchu_len);
        printf("加密后数据：%s\n",shuchu);
        char shuchu1[100] = {0};
        int shuchu1_len = 100;
        AES_128_CCM_decrypto_message(shuchu, shuchu_len, key, key_len, iv, iv_len, shuchu1, &shuchu1_len);
     
        //以下代码为差错控制检查:   
        char error_shuchu[71] = {'c'};
        int error_shuchu_len = 71;
        int iij = AES_128_CCM_decrypto_message(error_shuchu, error_shuchu_len, key, key_len, iv, iv_len, shuchu1, &shuchu1_len);
        printf("iij = %d\n",iij);
        //差错测试通过!!!!
        
        printf("解密后数据：%s\n",shuchu1);





		return 0;
}




