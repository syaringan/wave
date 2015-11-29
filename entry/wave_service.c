/**
 * @buf_beg:
 * @len:
 * @slen:
 * @len_r:
 * @
 */

#include<stdio.h>
#include "wave_service.h"
#include"../cme/cme.h"

#define ERROR_PRINTF(n) printf("n %s %d",__FILE__,__LINE__)

int do_client_request(struct sec_db* sdb,int fd){
    if(sdb == NULL){
        ERROR_PRINTF("参数错误");
        return -1;
    }

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
            if(do_cme_lsis_request(sdb) < 0)
                return -1;
            break;
        case CME_CMH_REQUEST:
            if(do_cme_cmh_request(sdb) < 0)
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
    }

    return 0;
}

static int do_cme_lsis_request(struct sec_db* sdb){
    if(sdb == NULL){
        ERROR_PRINTF("参数错误");
        return -1;
    }

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

static int do_cme_cmh_request(struct sec_db* sdb){
    if(sdb == NULL){
        ERROR_PRINTF("参数错误");
        return -1;
    }

    len = sizeof(int) + sizeof(cmh);
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

static int do_cme_generate_keypair(struct sec_db* sdb,int fd){
    if(sdb == NULL){
        ERROR_PRINTF("参数错误");
        return -1;
    }

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

    cmh cmh = *((cmh*)buf);
    buf += sizeof(cmh);

    int algorithm = *((int*)buf);

    free(buf_beg);

    string* pub_key_x;
    string* pub_key_y;
    INIT(*pub_key_x);
    INIT(*pub_key_y);

    int res = cme_generate_keypair(sdb,cmh,algorithm,pub_key_x,pub_key_y); //函数内部负责free string??
    if(res != 0){
        ERROR_PRINTF("cme_generate_keypair失败");
        return -1;
    }

    len = sizeof(int)*3 + pub_key_x->len + pub_key_y->len; //string里的len是pub_key的长度还是个数？？
    buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
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

    if(write(fd,buf,len) != len){
        ERROR_PRINTF("写入失败");
        free(buf_beg);
        return -1;
    }

    free(buf_beg);
    return 0;
}

static int do_cme_store_keypair(struct sec_db* sdb,int fd){
    if(sdb == NULL){
        ERROR_PRINTF("参数错误");
        return -1;
    }

    int len = 1024;
    char* buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }
    char* buf_beg = buf;

    int slen = 0
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

    cmh cmh = *((cmh*)buf);
    buf += sizeof(cmh);

    int algorithm = *((int*)buf);
    buf += 4;

    string* pub_key_x;              //需要初始化么？？
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

static int do_cme_store_cert(struct sec_db* sdb,int fd){
    if(sdb == NULL){
        ERROR_PRINTF("参数错误");
        return -1;
    }

    len = 1024;
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

    cmh cmh = *((cmh*)buf);
    buf += sizeof(cmh);

    int cert_len = *((int*)buf);
    buf += 4;

    certificate* cert;
    if(buf_2_certificate(buf,cert_len,cert) < 0){
        ERROR_PRINTF("buf_2_certificate失败");
        free(buf_beg);
        return -1;
    }
    buf += cert_len;

    string* transfor;
    transfor->len = *((int*)buf);
    buf += 4;
    transfor->buf = (char*)malloc(transfor->len);
    if(transfor->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        free(buf_beg);
        return -1;
    }
    memcpy(transfor->buf,buf,transfor->len);

    free(buf_beg);

    int res = cme_store_cert(sdb,cmh,cert,transfor);
    string_free(transfor);
    if(res != 0){
        ERROR_PRINTF("cme_store_cert失败");
        return -1;
    }

    return 0;
}

static int do_cme_store_cert_key(struct sec_db* sdb,int fd){
    if(sdb == NULL){
        ERROR_PRINTF("参数错误");
        reutrn -1;
    }

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

    cmh cmh = *((cmh*)buf);
    buf += sizeof(cmh);

    int cert_len = *((int*)buf);
    buf += 4;

    certificate* cert;
    if(buf_2_certificate(buf,cert_len,cert) < 0){
        ERROR_PRINTF("buf_2_certificate失败");
        free(buf_beg);
        return -1;
    }
    buf += cert_len;

    string* pri_key;
    pri_key->len = *((int*)buf);
    buf += 4;
    pri_key->buf = (char*)malloc(pri_key->len);
    if(pri_key->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        free(buf_beg);
        return -1;
    }
    memcpy(pri_key->buf,buf,pri_key->len);

    free(buf_beg);

    int res = cme_store_cert_key(sdb,cert,pri_key);
    string_free(pri_key);
    if(res != 0){
        ERROR_PRINTF("cme_store_cert_key失败");
        return -1;
    }

    return 0;
}

///////////////////////////////////////////////////////

static int do_sec_signed_data(struct sec_db* sdb,int fd){
    if(sdb == NULL){
        ERROR_PRINTF("参数错误");
        return -1;
    }

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

    cmh cmh = *((cmh*)buf);
    buf += sizeof(cmh);

    content_type type = *((int*)buf);
    buf += 4;

    string* data;
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
    exter_data->len = *((int*)buf);
    buf += 4;
    exter_data->buf = (char*)malloc(exter_data->len);
    if(exter_data->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        string_free(data);
        free(buf_beg);
    }
    memcpy(exter_data->buf,buf,exter_data->len);
    buf += exter_data->len;

    psid psid = *((psid*)buf);
    buf += sizeof(psid);

    string* ssp;
    ssp->len = *((int*)buf);
    buf += 4;
    ssp->buf = (char*)malloc(ssp->len);
    if(ssp->buf == NULL){
        ERROR_PRINTF("内存分配失败");
        string_free(data);
        string_free(exter_data);
        free(buf_beg);
    }
    memcpy(ssp->buf,buf,ssp->len);
    buf += ssp->len;

    bool set_geneartion_time = *((int*)buf);
    buf += 4;

    time64_with_standard_deviation* generation_time;
    generation_time->time = *((time64*)buf);
    buf += sizeof(time64);
    generation_time->long_std_dev = *buf++;

    bool set_generation_location = *((int*)buf);
    buf += 4;

    three_d_location* location;
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
    buf == 4;

    *((int*)buf) = signed_data->len;
    buf += 4;

    memcpy(buf,signed_data->buf,signed_data->len);
    buf += signed_data->len;

    *((int*)buf) = len_of_cert_chain;

    string_free(signed_data);

    if(write(fd,buf,len) != len){
        ERROR_PRINTF("写入失败");
        free(buf_beg);
        return -1;
    }

    free(buf_beg);
    return 0;
}

static int do_sec_encrypted_data(struct sec_db* sdb,int fd){
    if(sdb == NULL){
        ERROR_PRINTF("参数错误");
        return -1;
    }

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

    content_type type = *((int*)buf);
    buf += 4;

    string* data;
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

    struct certificate_chain* certs;
    certs->len = *((int*)buf);
    buf += 4;
    if(buf_2_certificate(buf,certs->len,certs->certs) < 0){
        ERROR_PRINTF("buf_2_certificate失败");
        string_free(data);
        free(buf_beg);
        return -1;
    }
    buf += certs->len;

    bool compressed = *((int*)buf);
    buf += 4;

    time64 time = *((time64*)buf);

    free(buf_beg);

    string* encrypted_data;
    INIT(*encrypted_data);
    struct certificate_chain* failed_certs;

    int res = sec_encrypted_data(sdb,type,data,certs,compressed,time,
                                encrypted_data,failed_certs);
    string_free(data);
    if(res != 0){
        ERROR_PRINTF("sec_encrypted_data失败");
        return -1;
    }

    len = sizeof(int)*3 + encrypted_data->len + failed_certs->len;
    buf = (char*)malloc(len);
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        return -1;
    }
    buf_beg = buf;

    *((int*)buf) = len - 4;
    buf += 4;

    *((int*)buf) = encrypted_data->len;
    buf += 4;

    memcpy(buf,encrypted_data->buf,encrypted_data->len);
    buf += encrypted_data->len;

    *((int*)buf) = failed_certs->len;
    buf += 4;

    memcpy(buf,failed_certs->certs,failed_certs->len);

    string_free(encrypted_data);

    if(write(fd,buf,len) != len){
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
static int do_sec_secure_data_content_extration(struct sec_db* sdb,int fd){
    if(sdb == NULL){
        ERROR_PRINTF("参数错误");
        return -1;
    }

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

    cmh cmh = *((cmh*)buf);

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

    INIT(data);
    INIT(signed_data);
    INIT(ssp);

    int res = sec_secure_data_content_extration(sdb,recieve_data,cmh
            &type,&inner_type,data,signed_data,&psid,ssp,&set_geneartion_time,
            generation_time,&set_expiry_time,&expiry_time,&set_generation_location,
            location,send_cert);
    string_free(recieve_data);
    if(res != 0){
        ERROR_PRINTF("sec_secure_data_content_extration失败");
        string_free(data);
        string_free(signed_data);
        string_free(ssp);
        return -1;
    }
    if((set_geneartion_time != 0 && set_geneartion_time != 1) ||
        (set_expiry_time != 0 && set_expiry_time != 1) ||
        (set_generation_location != 0 && set_generation_location != 1)){
        ERROR_PRINTF("返回参数错误");
        string_free(data);
        string_free(signed_data);
        string_free(ssp);
        return -1;
    }

    //将send_cert转换为数据流，并计算数据长度
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
            return -1;
        }
        else if(res == -2){
            send_cert_len *= 2;
            cert_buf = (char*)realloc(cert_buf,send_cert_len);
        }
    }
    send_cert_len = res;

    len = sizeof(int)*10 + sizeof(psid) + sizeof(time64) + 3 + data->len + signed_data->len + ssp->len + send_cert_len;
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

    //数据未处理

}

static int do_sec_signed_data_verification(struct sec_db* sdb,int fd);
