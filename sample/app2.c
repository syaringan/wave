#include<wave/wave_sec.h>
#include<stdio.h>
#include<stdlib.h>
#include"msocket.h"
#include<string.h>
#define MY_PORT 2010
#define OPP_PORT 2000
#define BUF_LEN 1024
#define error() printf("error %s %d\n",__FILE__,__LINE__);
#define INIT(n) memset(&n,0,sizeof(n))
typedef struct string{
    unsigned char* buf;
    int len;
}string;
static void string_malloc(string* data){
    data->len = 1024;
    data->buf = (char*)malloc(data->len);
    if(data->buf == NULL){
        printf("wave malloc fail %s %d\n",__FILE__,__LINE__);
        return;
    }
}
static void string_printf(char* name,string* data){
    printf("%s len:%d\n\r",name,data->len);
    int i;
    for(i=0;i<data->len;i++){
       printf("%02x ",(unsigned char)(data->buf[i]));
        if((i+1)%10==0)
           printf("\n"); 
    }
    printf("\n");
}
static int verification_signed_data(cme_lsis mlsis,string* rec_data,int type,psid psid,time64 generation_time,unsigned char lsd,
        time64 expiry_time,int generation_latitude,int generation_longtitude,unsigned char* elevation){
    int max_cert_chain_len = 3;
    int detect_reply = 1;
    int check_generation_time =1;
    time64 validity_time = 1000*1000*60*60*1;
    float  generation_thresold = 0.9;
    time64 accepte_time =  (time64)time(NULL)*1000000+1*60*1000000;
    float accepte_thresold = 0.9;
    int check_expiry_time = 1;
    float expiry_threshold = 0.9;
    int check_generation_location = 1;
    int latitude = 0;
    int longtitude = 0;
    unsigned int validity_distance = 100;
    time64 overdue_crl_tolerance = (time64)1*60*60*1000000;

    string cert;
    string_malloc(&cert);

    int res;
    res = sec_signed_data_verification(mlsis,psid,type,rec_data->buf,rec_data->len,NULL,0,
            max_cert_chain_len,detect_reply,check_generation_time,validity_time,generation_time,lsd,generation_thresold,
            accepte_time,accepte_thresold,check_expiry_time,expiry_time,expiry_threshold,check_generation_location,latitude,longtitude,
            validity_distance,generation_latitude,generation_longtitude,elevation,overdue_crl_tolerance,NULL,NULL,NULL,NULL,
            cert.buf,&cert.len);
    if(res){
        printf("verification fail res :%d %s %d\n",res,__FILE__,__LINE__);
        return -1;
    }
    printf("verification success %s %d\n",__FILE__,__LINE__);
    string_printf("signed cert:",&cert);
    return 0;
}
static void sec_data_parse(string *rec_data){
    int type,inner_type,res;
    string data,signed_data,ssp,send_cert;
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
    
    res = sec_secure_data_content_extration(rec_data->buf,rec_data->len,0,
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

    verification_signed_data(1,&signed_data,type,psid,generation_time,generation_long_std_dev,expiry_time,latitude,longtitude,elevation);
}
static void encrypted_data(string* cert){
    string data;
    data.len = 4;
    data.buf = (char*)malloc(data.len);
    if(data.buf == NULL){
        error();
        return;
    }
    data.buf[0] = 'l';
    data.buf[1] = 'j';
    data.buf[2] = 'h';
    data.buf[3] = '\0';
    int type = UNSECURED;
    int compressed = 0;
    time64 overdue_crl_tolerance =(time64)3600*1000000;

    string encrypted_data;
    encrypted_data.len = 2048;
    encrypted_data.buf = (char*)malloc(encrypted_data.len);
    if(encrypted_data.buf == NULL){
        error();
        return;
    }
    int res = sec_encrypted_data(type,data.buf,data.len,cert->buf,1,cert->len,compressed,overdue_crl_tolerance,
            
            encrypted_data.buf,&encrypted_data.len,NULL,NULL,NULL);
    if(res != 0){
        printf("sec_encrypted_data fail: res:%d\n",res);
    }
    else
         printf("sec_encrypted_data success\n");
}
int main(){
    cmh mcmh;
    cme_lsis mlsis;
    int fd;
    fd = getsocket(MY_PORT);
    if(fd <0 ){
        error();
        return -1;
    }
    
    if( cme_cmh_request(&mcmh)){
        error();
        return-1;
    }
    printf("cmh = %d\n",mcmh);
    if( cme_lsis_request(&mlsis)){
        error();
        return -1;
    }
    printf("lsis = %d\n",mlsis);
    string ocert,data;
    string_malloc(&ocert);
    string_malloc(&data);
    ocert.len = mrecvfrom(fd,ocert.buf,ocert.len,OPP_PORT);
    data.len = mrecvfrom(fd,data.buf,data.len,OPP_PORT);
    sec_data_parse(&data);
    string_printf("ocert",&ocert);
    encrypted_data(&ocert);
    //verification_signed_data(mlsis,&data);

  //  string_printf("recieve data",&data);
}
