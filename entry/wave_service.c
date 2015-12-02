#include<stdio.h>
#include "wave_service.h"
#include"cme/cme.h"
#include"sec/sec.h"

#define ERROR_PRINTF(n) printf("n %s %d",__FILE__,__LINE__)

int do_client_request(struct sec_db* sdb,int fd)
{
    int len = sizeof(app_tag);
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }

    int slen = 0;
    int len_r = 0;
    while(slen != len){
        len_r = read(fd,buf+slen,len-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf);
            return -1;
        }
        slen += len_r;
    }

    app_tag tag = *((app_tag*)buf);
    free(buf);

    switch(tag){
        case CME_LSIS_REQUEST:
            if(do_cme_lsis_request(sdb,fd) < 0)
                return -1;
            break;
        case CME_CMH_REQUEST:
            if(do_cme_cmh_request(sdb,fd) < 0)
                return -1;
            break;
        case CME_GENERATE_KEYPARI:
            if(do_cme_generate_keypair(sdb,fd) < 0)
                return -1;
            break;
        case CME_STORE_CERT:
            if(do_cme_store_cert(sdb,fd) < 0)
                return -1;
            break;
        case CME_STORE_CERT_KEY:
            if(do_cme_store_cert_key(sdb,fd) < 0)
                return -1;
            break;
        case SEC_SIGNED_DATA:
            if(do_sec_signed_data(sdb,fd) < 0)
                return -1;
            break;
        case SEC_ENCRYPTED_DATA:
            if(do_sec_encrypted_data(sdb,fd) < 0)
                return -1;
            break;
        case SEC_SECURE_DATA_CONTENT_EXTRATION:
            if(do_sec_secure_data_content_extration(sdb,fd) < 0)
                return -1;
            break;
        case SEC_SIGNED_DATA_VERIFICATION:
            if(do_sec_signed_data_verification(sdb,fd) < 0)
                return -1;
            break;
        default:
            ERROR_PRINTF("tag错误");
            return -1;
    }

    return 0;
}


static int do_cme_lsis_request(struct sec_db* sdb,int fd)
{
    int len = sizeof(int) + sizeof(cme_lsis);
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }

    *((int*)buf) = sizeof(cme_lsis);

    if(cme_lsis_request(sdb,(cme_lsis*)(buf+4)) != 0){
        ERROR_PRINTF("cme_lsis_request失败");
        free(buf);
        return -1;
    }

    if(write(fd,buf,len) != len){
        ERROR_PRINTF("写入失败");
        free(buf);
        return -1;
    }
    
    free(buf);
    return 0;
}


static int do_cme_cmh_request(struct sec_db* sdb,int fd)
{
    int len = sizeof(int) + sizeof(cmh);
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }

    *((int*)buf) = sizeof(cmh);

    if(cme_cmh_request(sdb,(cmh*)(buf+4)) != 0){
        ERROR_PRINTF("cme_cmh_request失败");
        free(buf);
        return -1;
    }

    if(write(fd,buf,len) != len){
        ERROR_PRINTF("写入失败");
        free(buf);
        return -1;
    }

    free(buf);
    return 0;
}


static int do_cme_generate_keypair(struct sec_db* sdb,int fd)
{
    int len = sizeof(int)*2 + sizeof(cmh);
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }
    char* buf_beg = buf;

    int slen = 0;
    int len_r;
    while(slen != len){
        len_r = read(fd,buf+slen,len-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    buf += 4;  //跳过长度

    cmh cmh;
    memcpy(&cmh,buf,sizeof(cmh));
    buf += sizeof(cmh);

    int algorithm = *((int*)buf);

    free(buf_beg);

    string* pub_key_x;
    string* pub_key_y;
    INIT(*pub_key_x);
    INIT(*pub_key_y);

    int res = cme_generate_keypair(sdb,cmh,algorithm,pub_key_x,pub_key_y);
    if(res != 0){
        ERROR_PRINTF("cme_generate_keypair失败");
        string_free(pub_key_x);
        string_free(pub_key_y);
        return -1;
    }

    len = sizeof(int)*3 + pub_key_x->len + pub_key_y->len;
    buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        string_free(pub_key_x);
        string_free(pub_key_y);
        return -1;
    }
    buf_beg = buf;

    *((int*)buf) = len - 4;
    buf += 4;

    *((int*)buf) = pub_key_x->len;
    buf += 4;

    memcpy(buf,pub_key_x->buf,pub_key_x->len);
    buf += pub_key_x->len;

    *((int*)buf) = pub_key_y->len;
    buf += 4;

    memcpy(buf,pub_key_y->buf,pub_key_y->len);

    string_free(pub_key_x);
    string_free(pub_key_y);

    if(write(fd,buf_beg,len) != len){
        ERROR_PRINTF("写入失败");
        free(buf_beg);
        return -1;
    }

    free(buf_beg);
    return 0;
}


static int do_cme_store_keypair(struct sec_db* sdb,int fd)
{
    int len = 1024;
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }
    char* buf_beg = buf;

    int slen = 0;
    int len_r;
    while(slen != 4){
        len_r = read(fd,buf+slen,4-slen);  //读取数据长度
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    len = *((int*)buf);
    if(len > 1020){
        buf = (char*)realloc(buf,len + 4);
        buf_beg = buf;
    }
    slen = 0;
    buf += 4;

    while(slen != len){
        len_r = read(fd,buf+slen,len-slen);  //读取数据
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    cmh cmh;
    memcpy(&cmh,buf,sizeof(cmh));
    buf += sizeof(cmh);

    int algorithm = *((int*)buf);
    buf += 4;

    string* pub_key_x;
    INIT(*pub_key_x);
    pub_key_x->len = *((int*)buf);
    buf += 4;
    pub_key_x->buf = (char*)malloc(pub_key_x->len);
    if(pub_key_x->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        free(buf_beg);
        return -1;
    }
    memcpy(pub_key_x->buf,buf,pub_key_x->len);
    buf += pub_key_x->len;

    string* pub_key_y;
    INIT(*pub_key_y);
    pub_key_y->len = *((int*)buf);
    buf += 4;
    pub_key_y->buf = (char*)malloc(pub_key_y->len);
    if(pub_key_y->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        free(buf_beg);
        string_free(pub_key_x);
        return -1;
    }
    memcpy(pub_key_y->buf,buf,pub_key_y->len);
    buf += pub_key_y->len;

    string* pri_key;
    INIT(*pri_key);
    pri_key->len = *((int*)buf);
    buf += 4;
    pri_key->buf = (char*)malloc(pri_key->len);
    if(pri_key->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        free(buf_beg);
        string_free(pub_key_x);
        string_free(pub_key_y);
        return -1;
    }
    memcpy(pri_key->buf,buf,pri_key->len);
    buf += pri_key->len;

    free(buf_beg);

    int res = cme_store_keypair(sdb,cmh,algorithm,pub_key_x,pub_key_y,pri_key);
    string_free(pub_key_x);
    string_free(pub_key_y);
    string_free(pri_key);
    if(res != 0){
        ERROR_PRINTF("cme_store_keypair失败");
        return -1;
    }

    return 0;
}


static int do_cme_store_cert(struct sec_db* sdb,int fd)
{
    int len = 1024;
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }
    char* buf_beg = buf;

    int slen = 0;
    int len_r;
    while(slen != 4){
        len_r = read(fd,buf+slen,4-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    len = *((int*)buf);
    if(len > 1020){
        buf = (char*)realloc(buf,len + 4);
        buf_beg = buf;
    }
    slen = 0;
    buf += 4;

    while(slen != len){
        len_r = read(fd,buf+slen,len-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    cmh cmh;
    memcpy(&cmh,buf,sizeof(cmh));
    buf += sizeof(cmh);

    int cert_len = *((int*)buf);
    buf += 4;

    certificate* cert;
    INIT(*cert);
    if(buf_2_certificate(buf,cert_len,cert) < 0){
        ERROR_PRINTF("buf_2_certificate失败");
        certificate_free(cert);
        free(buf_beg);
        return -1;
    }
    buf += cert_len;

    string* transfor;
    INIT(*transfor);
    transfor->len = *((int*)buf);
    buf += 4;
    transfor->buf = (char*)malloc(transfor->len);
    if(transfor->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        certificate_free(cert);
        free(buf_beg);
        return -1;
    }
    memcpy(transfor->buf,buf,transfor->len);

    free(buf_beg);

    int res = cme_store_cert(sdb,cmh,cert,transfor);
    certificate_free(cert);
    string_free(transfor);
    if(res != 0){
        ERROR_PRINTF("cme_store_cert失败");
        return -1;
    }

    return 0;
}


static int do_cme_store_cert_key(struct sec_db* sdb,int fd)
{
    int len = 1024;
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }
    char* buf_beg = buf;

    int slen = 0;
    int len_r;
    while(slen != 4){
        len_r = read(fd,buf+slen,4-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    len = *((int*)buf);
    if(len > 1020){
        buf = (char*)realloc(buf,len + 4);
        buf_beg = buf;
    }
    slen = 0;
    buf += 4;

    while(slen != len){
        len_r = read(fd,buf+slen,len-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取错误");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    cmh cmh;
    memcpy(&cmh,buf,sizeof(cmh));
    buf += sizeof(cmh);

    int cert_len = *((int*)buf);
    buf += 4;

    certificate* cert;
    INIT(*cert);
    if(buf_2_certificate(buf,cert_len,cert) < 0){
        ERROR_PRINTF("buf_2_certificate失败");
        certificate_free(cert);
        free(buf_beg);
        return -1;
    }
    buf += cert_len;

    string* pri_key;
    INIT(*pri_key);
    pri_key->len = *((int*)buf);
    buf += 4;
    pri_key->buf = (char*)malloc(pri_key->len);
    if(pri_key->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        certificate_free(cert);
        free(buf_beg);
        return -1;
    }
    memcpy(pri_key->buf,buf,pri_key->len);

    free(buf_beg);

    int res = cme_store_cert_key(sdb,cert,pri_key);
    certificate_free(cert);
    string_free(pri_key);
    if(res != 0){
        ERROR_PRINTF("cme_store_cert_key失败");
        return -1;
    }

    return 0;
}


static int do_sec_signed_data(struct sec_db* sdb,int fd)
{
    int len = 1024;
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }
    char* buf_beg = buf;

    int slen = 0;
    int len_r;
    while(slen != 4){
        len_r = read(fd,buf+slen,4-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    len = *((int*)buf);
    if(len > 1020){
        buf = (char*)realloc(buf,len + 4);
        buf_beg = buf;
    }
    slen = 0;
    buf += 4;

    while(slen != len){
        len_r = read(fd,buf+slen,len-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    cmh cmh;
    memcpy(&cmh,buf,sizeof(cmh));
    buf += sizeof(cmh);

    content_type type = *((int*)buf);
    buf += 4;

    string* data;
    INIT(*data);
    data->len = *((int*)buf);
    buf += 4;
    data->buf = (char*)malloc(data->len);
    if(data->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        free(buf_beg);
        return -1;
    }
    memcpy(data->buf,buf,data->len);
    buf += data->len;

    string* exter_data;
    INIT(*exter_data);
    exter_data->len = *((int*)buf);
    buf += 4;
    exter_data->buf = (char*)malloc(exter_data->len);
    if(exter_data->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        string_free(data);
        free(buf_beg);
        return -1;
    }
    memcpy(exter_data->buf,buf,exter_data->len);
    buf += exter_data->len;

    psid psid;
    memcpy(&psid,buf,sizeof(psid));
    buf += sizeof(psid);

    string* ssp;
    INIT(*ssp);
    ssp->len = *((int*)buf);
    buf += 4;
    ssp->buf = (char*)malloc(ssp->len);
    if(ssp->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        string_free(data);
        string_free(exter_data);
        free(buf_beg);
        return -1;
    }
    memcpy(ssp->buf,buf,ssp->len);
    buf += ssp->len;

    bool set_geneartion_time = *((int*)buf);
    buf += 4;

    time64_with_standard_deviation* generation_time;
    INIT(*generation_time);
    generation_time->time = *((time64*)buf);
    buf += sizeof(time64);
    generation_time->long_std_dev = *buf++;

    bool set_generation_location = *((int*)buf);
    buf += 4;

    three_d_location* location;
    INIT(*location);
    location->latitude = *((int*)buf);
    buf += 4;
    location->longtitude = *((int*)buf);
    buf += 4;
    memcpy(location->elevation,buf,2);
    buf += 2;

    bool set_expiry_time = *((int*)buf);
    buf += 4;

    time64 expiry_time = *((time64*)buf);
    buf += sizeof(time64);

    enum signed_data_signer_type signer_type = *((int*)buf);
    buf += 4;

    s32 cert_chain_len = *((int*)buf);
    buf += 4;

    u32 cert_chain_max_len = *((int*)buf);
    buf += 4;

    enum sign_with_fast_verification fs_type = *((int*)buf);
    buf += 4;

    bool compressed = *((int*)buf);

    free(buf_beg);

    string* signed_data;
    INIT(*signed_data);
    u32 len_of_cert_chain;

    int res = sec_signed_data(sdb,cmh,type,data,exter_data,psid,
                            ssp,set_geneartion_time,generation_time,
                            set_generation_location,location,set_expiry_time,expiry_time,
                            signer_type,cert_chain_len,cert_chain_max_len,fs_type,compressed,
                            
                            signed_data,&len_of_cert_chain);
    string_free(data);
    string_free(exter_data);
    string_free(ssp);
    if(res != 0){
        ERROR_PRINTF("sec_signed_data失败");
        return -1;
    }

    len = sizeof(int)*3 + signed_data->len;
    buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }
    buf_beg = buf;

    *((int*)buf) = len - 4;
    buf += 4;

    *((int*)buf) = signed_data->len;
    buf += 4;

    memcpy(buf,signed_data->buf,signed_data->len);
    buf += signed_data->len;

    *((int*)buf) = len_of_cert_chain;

    string_free(signed_data);

    if(write(fd,buf_beg,len) != len){
        ERROR_PRINTF("写入失败");
        free(buf_beg);
        return -1;
    }

    free(buf_beg);
    return 0;
}


static int do_sec_encrypted_data(struct sec_db* sdb,int fd)
{
    int len = 1024;
    int count = 0;
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }
    char* buf_beg = buf;

    int slen = 0;
    int len_r;
    while(slen != 4){
        len_r = read(fd,buf+slen,4-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    len = *((int*)buf);
    if(len > 1020){
        buf = (char*)realloc(buf,len + 4);
        buf_beg = buf;
    }
    slen = 0;
    buf += 4;

    while(slen != len){
        len_r = read(fd,buf+slen,len-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    content_type type = *((int*)buf);
    buf += 4;
    count += 4;

    string* data;
    INIT(*data);
    data->len = *((int*)buf);
    buf += 4;
    data->buf = (char*)malloc(data->len);
    if(data->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        free(buf_beg);
        return -1;
    }
    memcpy(data->buf,buf,data->len);
    buf += data->len;
    count += (4 + data->len);

    struct certificate_chain* certs;
    INIT(certs);
    certs->len = *((int*)buf);
    buf += 4;
    count += 4;

    int i,j;
    int cert_len;
    for(i=0;i<certs->len;i++){
        cert_len = buf_2_certificate(buf,len-count,certs->certs+i);
        if(cert_len < 0){
            ERROR_PRINTF("buf_2_certificate失败");
            certificate_chain_free(certs);
            string_free(data);
            free(buf_beg);
            return -1;
        }
        buf += cert_len;
        count += cert_len;
    }
    
    bool compressed = *((int*)buf);
    buf += 4;

    time64 time = *((time64*)buf);

    free(buf_beg);

    string* encrypted_data;
    struct certificate_chain* failed_certs;
    INIT(*encrypted_data);
    INIT(*failed_certs);

    int res = sec_encrypted_data(sdb,type,data,certs,compressed,time,
                                encrypted_data,failed_certs);
    certificate_chain_free(certs);
    string_free(data);
    if(res != 0){
        ERROR_PRINTF("sec_encrypted_data失败");
        string_free(encrypted_data);
        certificate_chain_free(failed_certs);
        return -1;
    }

    len = sizeof(int)*3 + encrypted_data->len + failed_certs->len*sizeof(certificate); //??
    buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        string_free(encrypted_data);
        certificate_chain_free(failed_certs);
        return -1;
    }
    buf_beg = buf;
    count = 0;

    buf += 4;
    count += 4;

    *((int*)buf) = encrypted_data->len;
    buf += 4;
    count += 4;

    memcpy(buf,encrypted_data->buf,encrypted_data->len);
    buf += encrypted_data->len;
    count += encrypted_data->len;

    *((int*)buf) = failed_certs->len;
    buf += 4;
    count += 4;

    for(i=0;i<failed_certs->len;i++){
        cert_len = certificate_2_buf(failed_certs->certs+i,buf,len-count);
        if(cert_len > 0){
            buf += cert_len;
            count += cert_len;
        }
        else if(cert_len == -2){
            len *= 2;
            buf_beg = (char*)realloc(buf_beg,len);
            buf = buf_beg + count;
            i--;  //重新对该证书进行转换
        }
        else if(cert_len < 0){
            ERROR_PRINTF("certificate_2_buf失败");
            certificate_chain_free(failed_certs);
            string_free(encrypted_data);
            free(buf_beg);
            return -1;
        }
    }


    *((int*)buf_beg) = count - 4;
    certificate_chain_free(failed_certs);
    string_free(encrypted_data);

    if(write(fd,buf_beg,len) != len){
        ERROR_PRINTF("写入失败");
        free(buf_beg);
        return -1;
    }

    free(buf_beg);
    return 0;
}

/**
 * @set_geneartion_time/set_expiry_time/set_generation_location:只能为0或者1
 * @elevation:默认是两字节，只能为两字节
 */
static int do_sec_secure_data_content_extration(struct sec_db* sdb,int fd)
{
    int len = 1024;
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }
    char* buf_beg = buf;

    int slen = 0;
    int len_r;
    while(slen != 4){
        len_r = read(fd,buf+slen,4-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    len = *((int*)buf);
    if(len > 1020){
        buf = (char*)realloc(buf,len + 4);
        buf_beg = buf;
    }
    slen = 0;
    buf += 4;

    while(slen != len){
        len_r = read(fd,buf+slen,len-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    string* recieve_data;
    INIT(*recieve_data);
    recieve_data->len = *((int*)buf);
    buf += 4;
    recieve_data->buf = (char*)malloc(recieve_data->len);
    if(recieve_data->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        free(buf_beg);
        return -1;
    }
    memcpy(recieve_data->buf,buf,recieve_data->len);
    buf += recieve_data->len;

    cmh cmh;
    memcpy(&cmh,buf,sizeof(cmh));

    free(buf_beg);

    content_type type;
    content_type inner_type;
    string* data;
    string* signed_data;
    psid psid;
    string* ssp;
    bool set_geneartion_time;
    time64_with_standard_deviation* generation_time;
    bool set_expiry_time;
    time64 expiry_time;
    bool set_generation_location;
    three_d_location* location;
    certificate* send_cert;

    INIT(*data);
    INIT(*signed_data);
    INIT(*ssp);
    INIT(*generation_time);
    INIT(*location);
    INIT(*send_cert);

    int res = sec_secure_data_content_extration(sdb,recieve_data,cmh,
            &type,&inner_type,data,signed_data,&psid,ssp,&set_geneartion_time,
            generation_time,&set_expiry_time,&expiry_time,&set_generation_location,
            location,send_cert);
    string_free(recieve_data);
    if(res != 0){
        ERROR_PRINTF("sec_secure_data_content_extration失败");
        string_free(data);
        string_free(signed_data);
        string_free(ssp);
        certificate_free(send_cert);
        return -1;
    }
    if((set_geneartion_time != 0 && set_geneartion_time != 1) ||
        (set_expiry_time != 0 && set_expiry_time != 1) ||
        (set_generation_location != 0 && set_generation_location != 1)){
        ERROR_PRINTF("返回参数错误");
        string_free(data);
        string_free(signed_data);
        string_free(ssp);
        certificate_free(send_cert);
        return -1;
    }

    //将send_cert转换为数据流，并计算数据长度，之后将certificate释放
    int send_cert_len = 1024;
    char* cert_buf = (char*)malloc(len);
    res = -2;
    while(res == -2){ //分配内存不够
        res = certificate_2_buf(send_cert,cert_buf,send_cert_len);
        if(res == -1){
            ERROR_PRINTF("certificate_2_buf失败");
            free(cert_buf);
            string_free(data);
            string_free(signed_data);
            string_free(ssp);
            certificate_free(send_cert);
            return -1;
        }
        else if(res == -2){
            send_cert_len *= 2;
            cert_buf = (char*)realloc(cert_buf,send_cert_len);
        }
    }
    certificate_free(send_cert);
    send_cert_len = res;

    len = sizeof(int)*11 + sizeof(psid) + sizeof(time64)*2 + 3 + data->len + signed_data->len + ssp->len + send_cert_len;
    buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        free(cert_buf);
        string_free(data);
        string_free(signed_data);
        string_free(ssp);
        return -1;
    }
    buf_beg = buf;

    *((int*)buf) = len - 4;
    buf += 4;

    *((int*)buf) = type;
    buf += 4;

    *((int*)buf) = inner_type;
    buf += 4;

    *((int*)buf) = data->len;
    buf += 4;

    memcpy(buf,data->buf,data->len);
    buf += data->len;

    *((int*)buf) = signed_data->len;
    buf += 4;

    memcpy(buf,signed_data->buf,signed_data->len);
    buf += signed_data->len;

    memcpy(buf,&psid,sizeof(psid));
    buf += sizeof(psid);

    *((int*)buf) = ssp->len;
    buf += 4;

    memcpy(buf,ssp->buf,ssp->len);
    buf += ssp->len;

    *((int*)buf) = set_geneartion_time;
    buf += 4;

    *((time64*)buf) = generation_time->time;
    buf += sizeof(time64);

    *buf++ = generation_time->long_std_dev;

    *((int*)buf) = set_expiry_time;
    buf += 4;

    *((time64*)buf) = expiry_time;
    buf += sizeof(time64);

    *((int*)buf) = set_generation_location;
    buf += 4;

    *((int*)buf) = location->latitude;
    buf += 4;

    *((int*)buf) = location->longtitude;

    memcpy(buf,location->elevation,2);
    buf += 2;

    memcpy(buf,cert_buf,send_cert_len);
    
    free(cert_buf);
    string_free(data);
    string_free(signed_data);
    string_free(ssp);

    if(write(fd,buf_beg,len) != len){
        ERROR_PRINTF("写入失败");
        free(buf_beg);
        return -1;
    }

    free(buf_beg);
    return 0;
}

static int do_sec_signed_data_verification(struct sec_db* sdb,int fd)
{
    int len = 1024;
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }
    char* buf_beg = buf;

    int slen = 0;
    int len_r;
    while(slen != 4){
        len_r = read(fd,buf+slen,4-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    len = *((int*)buf);
    if(len > 1020){
        buf = (char*)realloc(buf,len + 4);
        buf_beg = buf;
    }
    slen = 0;
    buf += 4;

    while(slen != len){
        len_r = read(fd,buf+slen,len-slen);
        if(len_r <= 0){
            ERROR_PRINTF("读取失败");
            free(buf_beg);
            return -1;
        }
        slen += len_r;
    }

    cme_lsis lsis = *((cme_lsis*)buf);
    buf += sizeof(cme_lsis);

    psid psid;
    memcpy(&psid,buf,sizeof(psid));
    buf += sizeof(psid);

    content_type type = *((int*)buf);
    buf += 4;

    string* signed_data;
    INIT(*signed_data);
    signed_data->len = *((int*)buf);
    buf += 4;
    signed_data->buf = (char*)malloc(signed_data->len);
    if(signed_data->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        free(buf_beg);
        return -1;
    }
    memcpy(signed_data->buf,buf,signed_data->len);
    buf += signed_data->len;

    string* external_data;
    INIT(*external_data);
    external_data->len = *((int*)buf);
    buf += 4;
    external_data->buf = (char*)malloc(external_data->len);
    if(external_data->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        string_free(signed_data);
        free(buf_beg);
        return -1;
    }
    memcpy(external_data->buf,buf,external_data->len);
    buf += external_data->len;

    u32 max_cert_chain_len = *((int*)buf);
    buf += 4;

    bool detect_reply = *((int*)buf);
    buf += 4;

    bool check_generation_time = *((int*)buf);
    buf += 4;

    time64 validity_period = *((time64*)buf);
    buf += sizeof(time64);

    time64_with_standard_deviation* generation_time;
    INIT(*generation_time);
    generation_time->time = *((time64*)buf);
    buf += sizeof(time64);
    generation_time->long_std_dev = *buf++;

    float generation_threshold = *((float*)buf);
    buf += 4;

    time64 accepte_time = *((time64*)buf);
    buf += sizeof(time64);

    float accepte_threshold = *((float*)buf);
    buf += 4;

    bool check_expiry_time = *((int*)buf);
    buf += 4;

    time64 expiry_time = *((time64*)buf);
    buf += sizeof(time64);

    float exprity_threshold = *((float*)buf);
    buf += 4;

    bool check_generation_location = *((int*)buf);
    buf += 4;

    two_d_location* location;
    INIT(*location);
    location->latitude = *((int*)buf);
    buf += 4;
    location->longtitude = *((int*)buf);
    buf += 4;

    u32 validity_distance = *((int*)buf);
    buf += 4;

    three_d_location* generation_location;
    INIT(*generation_location);
    generation_location->latitude = *((int*)buf);
    buf += 4;
    generation_location->longtitude = *((int*)buf);
    buf += 4;
    memcpy(generation_location->elevation,buf,2);
    buf += 2;

    time64 overdue_crl_tolerance = *((time64*)buf);

    free(buf_beg);

    struct time32_array* last_recieve_crl_times;
    struct time32_array* next_expected_crl_times;
    certificate* send_cert;

    INIT(*last_recieve_crl_times);
    INIT(*next_expected_crl_times);
    INIT(*send_cert);

    int res = sec_signed_data_verification(sdb,lsis,&psid,type,
                    signed_data,external_data,max_cert_chain_len,
                    detect_reply,check_generation_time,validity_period,
                    generation_time,generation_threshold,accepte_time,accepte_threshold,
                    check_expiry_time,expiry_time,exprity_threshold,
                    check_generation_location,location,validity_distance,
                    generation_location,overdue_crl_tolerance,
                    
                    last_recieve_crl_times,next_expected_crl_times,send_cert);
    string_free(signed_data);
    string_free(external_data);
    if(res != 0){
        ERROR_PRINTF("sec_signed_data_verification失败");
        time32_array_free(last_recieve_crl_times);
        time32_array_free(next_expected_crl_times);
        certificate_free(send_cert);
        return -1;
    }

    int send_cert_len = 1024;
    char* cert_buf = (char*)malloc(len);
    res = -2;
    while(res == -2){ //分配内存不够
        res = certificate_2_buf(send_cert,cert_buf,send_cert_len);
        if(res == -1){
            ERROR_PRINTF("certificate_2_buf失败");
            time32_array_free(last_recieve_crl_times);
            time32_array_free(next_expected_crl_times);
            certificate_free(send_cert);
            return -1;
        }
        else if(res == -2){
            send_cert_len *= 2;
            cert_buf = (char*)realloc(cert_buf,send_cert_len);
        }
    }
    certificate_free(send_cert);
    send_cert_len = res;

    len = sizeof(int)*3 + sizeof(time32)*(last_recieve_crl_times->len + next_expected_crl_times->len) + send_cert_len;
    buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        time32_array_free(last_recieve_crl_times);
        time32_array_free(next_expected_crl_times);
        free(cert_buf);
        return -1;
    }
    buf_beg = buf;

    *((int*)buf) = len - 4;
    buf += 4;

    *((int*)buf) = last_recieve_crl_times->len;
    buf += 4;

    memcpy(buf,last_recieve_crl_times->times,sizeof(time32)*last_recieve_crl_times->len);
    buf += sizeof(time32)*last_recieve_crl_times->len;

    *((int*)buf) = next_expected_crl_times->len;
    buf += 4;

    memcpy(buf,next_expected_crl_times->times,sizeof(time32)*next_expected_crl_times->len);
    buf += sizeof(time32)*next_expected_crl_times->len;

    memcpy(buf,cert_buf,send_cert_len);

    free(cert_buf);
    time32_array_free(last_recieve_crl_times);
    time32_array_free(next_expected_crl_times);

    if(write(fd,buf_beg,len) != len){
        ERROR_PRINTF("写入失败");
        free(buf_beg);
        return -1;
    }

    free(buf_beg);
    return -1;
}


