#include<wave/wave_sec.h>
#include<stdio.h>
#include"msocket.h"
#include<stdlib.h>
#include<time.h>
#define MY_PORT 2000
#define OPP_PORT 2010
#define error() printf("error %s %d\n",__FILE__,__LINE__);

/**
 *  1.申请一个cmh
 *  2.然后去我自己做的工具生成的证书里面找一个
 *  3.存储到底层，
 *  4.发送我的证书给对面
 *  5.然后发送一个我签名信息给对面。
 *  6.接受对面的证书，用来加密。
 *  7.加密数据来发送给对面。
 */
struct string{
    char* buf;
    int len;
};

static int fd;
static void send_to(char*buf,int len){
    int mlen;
    mlen = msendto(fd,buf,len,OPP_PORT);
    if(mlen != len){
        error();
        return;
    }
    return;
}
static void getcert_and_key(struct string *cert,struct string *pri){
    FILE *fd;
    fd = fopen("../cert/issued_cert/sde1.cert","r");
    if(fd == NULL){
        error();
        return;
    }
    cert->len = 400;
    cert->buf = (char*)malloc(cert->len);
    if(cert->buf == NULL){
        error();
        return ;
    }
    cert->len = fread(cert->buf,1,cert->len,fd);
    if(cert->len <= 0){
        error();
        return;
    }
    fclose(fd);

    fd = fopen("../cert/issued_cert/sde1.veri.pri","r");
    if(fd == NULL){
        error();
        return;
    }
    pri->len = 100;
    pri->buf = (char*)malloc(pri->len);
    if(pri->buf == NULL){
        error();
        return ;
    }
    pri->len = fread(pri->buf,1,pri->len,fd);
    if(pri->len <= 0){
        error();
        return;
    }
    fclose(fd);
}
static void generated_signed_data(cmh cmh,struct string* sdata){
    sdata->len = 400;
    sdata->buf = (char*)malloc(sdata->len);
    if(sdata->buf == NULL){
        error();
        return ;
    }

    int type ;
    type = SIGNED;

    int psid ;
    psid = 0x20;
    
    time64 generate_time,expiry_time;
    generate_time = time(NULL) * 1000 * 1000;
    expiry_time = generate_time + (long long)1*24*60*60*1000*1000; 

    unsigned char glsd ;
    glsd = 0x10;

    int latitude ,longtitude;
    latitude = 0;
    longtitude = 0;
    char elevation[2];
    elevation[0] = 0;
    elevation[1] = 0xf0;

    int signer_type = SIGNED_DATA_CERTIFICATE;
    int cert_chain_len = 3,max_cert_len = 4;
    int fs_type = NO; 
    
    if(sec_signed_data(cmh,type,"123",3,NULL,0,psid,NULL,0,1,generate_time,glsd,1,latitude,longtitude,elevation,
                1,expiry_time,signer_type,cert_chain_len,max_cert_len,fs_type,1,
                
                sdata->buf,&sdata->len,NULL)){
        error();
    }

}
int main(){
    cmh mcmh;
    struct string mcert,mpri;
    struct string signed_data;
    fd = getsocket(MY_PORT);
    if(fd <0 ){
        error();
        return -1;
    }
    getcert_and_key(&mcert,&mpri);
    
    if( cme_cmh_request(&mcmh)){
        error();
        return-1;
    }
    if( cme_store_cert_key(mcmh,mcert.buf,mcert.len,mpri.buf,mpri.len)){
        error();
        return -1;
    }
    //generated_signed_data(mcmh,&signed_data);    
        
}
