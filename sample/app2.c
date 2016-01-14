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
static void sec_signed_data_parse(string *rec_data){
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
    string_printf("signed_data",&signed_data);
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

    string ocert,data;
    string_malloc(&ocert);
    string_malloc(&data);
    ocert.len = mrecvfrom(fd,ocert.buf,ocert.len,OPP_PORT);
    data.len = mrecvfrom(fd,data.buf,data.len,OPP_PORT);
    sec_signed_data_parse(&data);
    string_printf("ocert",&ocert);

    string_printf("recieve data",&data);
}
