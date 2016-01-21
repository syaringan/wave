#include<wave/wave_sec.h>
#include<stdio.h>
#include"msocket.h"
#include<stdlib.h>
#include<time.h>
#include<string.h>
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
    if(mlen){
        error();
        return;
    }
    return;
}
static void string_printf(char* name,struct string* data){
    printf("%s len:%d\n\r",name,data->len);
    int i;
    for(i=0;i<data->len;i++){
       printf("%02x ",(unsigned char)(data->buf[i]));
        if((i+1)%10==0)
           printf("\n"); 
    }
    printf("\n");
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
static int generated_signed_data(cmh cmh,struct string* sdata){
    sdata->len = 1024;
    sdata->buf = (char*)malloc(sdata->len);
    if(sdata->buf == NULL){
        error();
        return ;
    }
    memset(sdata->buf,1,sdata->len);
    int type ;
    type = SIGNED;

    psid psid ;
    psid = 0x20;
    
    time64 generate_time,expiry_time;
    generate_time = time(NULL) * 1000 * (time64)1000;
    expiry_time = generate_time + (time64)1*60*1000*1000; 
    printf("expiry_time:%llu\n",expiry_time);
    unsigned char glsd ;
    glsd = 0x10;

    int latitude ,longtitude;
    latitude = 0;
    longtitude = 0;
    char elevation[2];
    elevation[0] = 0;
    elevation[1] = 0xf0;

    int signer_type = SIGNED_DATA_CERTIFICATE;
    int cert_chain_len = 2,max_cert_len = 4;
    int fs_type = YES_UNCOMPRESSED; 
    
    if(sec_signed_data(cmh,type,"123",3,NULL,0,psid,"ljh",3,1,generate_time,glsd,1,latitude,longtitude,elevation,
                1,expiry_time,signer_type,cert_chain_len,max_cert_len,fs_type,1,
                
                sdata->buf,&sdata->len,NULL)){
        error();
        return -1;
    }
    return 0;
}
static void string_malloc(struct string* data){
    data->len = 1024;
    data->buf = (char*)malloc(data->len);
    if(data->buf == NULL){
        printf("wave malloc fail %s %d\n",__FILE__,__LINE__);
        return;
    }
}
static void sec_data_parse(struct string *rec_data,cmh mcmh){
    int type,inner_type,res;
    struct string data,signed_data,ssp,send_cert;
    psid psid;
    int set_generation_time,set_expiry_time,set_generation_location;
    time64 generation_time,expiry_time;
    unsigned char generation_long_std_dev;
    int latitude,longtitude;
    unsigned char elevation[2];



    string_malloc(&data);
    string_malloc(&signed_data);
    string_malloc(&ssp);
    string_malloc(&send_cert);
    
    res = sec_secure_data_content_extration(rec_data->buf,rec_data->len,mcmh,
                    &type,&inner_type,data.buf,&data.len,signed_data.buf,&signed_data.len,
                    &psid,ssp.buf,&ssp.len,&set_generation_time,&generation_time,
                    &generation_long_std_dev,&set_expiry_time,&expiry_time,&set_generation_location,
                    &latitude,&longtitude,elevation,send_cert.buf,&send_cert.len);
    if(res){
        printf("sec_secure_data_content_extration 失败\n");
        return;
    }
    int i;
    printf("type:%d  inner type : %d (0=UNSECURE,1=SIGNED,2=ENCRYPTED,9,10 = SIGNED_...)\n",type,inner_type);
    string_printf("data",&data);
   // string_printf("signed_data",&signed_data);
   printf("signed data len :%d\n",signed_data.len);
    printf("psid:%d\n",psid);
    string_printf("spp",&ssp);
    if(set_generation_time == 1){
        printf("generation time:%lluus\n",generation_time);
    }
    else
        printf("set_generation_time:%d\n",set_generation_time);

    printf("generation_long_std_dev:%d\n",generation_long_std_dev);
     if(set_expiry_time == 1){
        printf("expiry time:%lluus\n",expiry_time);
    }
    else
        printf("expiry_time:%d\n",set_expiry_time);
     if(set_generation_location == 1){
        printf("latitude:%d longtitude %d\n",latitude,longtitude);
    }
    else
        printf("set_generation_location:%d\n",set_generation_location);

    printf("elevation %u %u\n",elevation[0],elevation[1]);
    string_printf("send_cert",&send_cert);

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
    printf("cmh = %d\n",mcmh);
    if( cme_store_cert_key(mcmh,mcert.buf,mcert.len,mpri.buf,mpri.len)){
        error();
        return -1;
    }
    string_printf("mcert:",&mcert);
    printf("store cert and key\n");
    if(generated_signed_data(mcmh,&signed_data)){
        error();
        return -1;
    }
    printf("send cert\n");
    send_to(mcert.buf,mcert.len);
    printf("send data\n");
    send_to(signed_data.buf,signed_data.len);
    
    struct string encrypteddata;
    encrypteddata.len = 0;
    encrypteddata.buf = 0;
    encrypteddata.len = 1024;
    encrypteddata.buf = (char*)malloc(encrypteddata.len);
    if(encrypteddata.buf == NULL){
        error();
        return;
    }
    encrypteddata.len = mrecvfrom(fd,encrypteddata.buf,encrypteddata.len,OPP_PORT);
    string_printf("encryptd data",&encrypteddata);
    sec_data_parse(&encrypteddata,mcmh);    

}
