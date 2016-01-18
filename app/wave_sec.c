#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include"utils/common.h"
#include"wave_sec.h"
#include"utils/list.h"
#include<pthread.h>
#include<stddef.h>
#include"utils/af_unix.h"
#include<error.h>
#define SERVICE "/var/tmp/wave_sec.socket"

#define	ERROR_PRINTF(n) printf(n"%s %d\n",__FILE__,__LINE__)

static int getsocket(){
    int fd = -1;
    fd = cli_connect(SERVICE);
    return fd;
}

/**
 *请求实体的编号，lsis为null则不会有指填写，
 *@return 0成功 -1 失败
 */

int cme_lsis_request(cme_lsis* lsis){
	int fd;
    fd = getsocket();
    app_tag  tag = CME_LSIS_REQUEST;
    if(write(fd,&tag,sizeof(app_tag)) != sizeof(app_tag)){
        ERROR_PRINTF("写入失败");
        close(fd);
        return -1;
    }

	int slen = 0;
	int len = 4 + sizeof(cme_lsis);
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
        close(fd);
		return -1;
	}
	char* buf_beg = buf;

	int len_r;
    //判断函数调用是否成功
    while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            free(buf_beg);
            close(fd);
            return -1;
		}
		slen += len_r;
	}
    if(*((int*)buf) != 0){
        ERROR_PRINTF("B端函数调用失败");
        free(buf_beg);
        close(fd);
        return -1;
    }
    //读取数据长度
    slen=0;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            free(buf_beg);
			close(fd);
            return -1;
		}
		slen += len_r;
	}
	len = *((int*)buf);
	slen = 0;
	buf +=4;

	while(slen != len){
		len_r = read(fd,buf+slen,len-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            free(buf_beg);
			close(fd);
            return -1;
		}
		slen += len_r;
	}

	if(lsis != NULL){
		memcpy(lsis,buf,len);
	}

	free(buf_beg);
	close(fd);
    return 0;
}

int cme_cmh_request(cmh* cmh){
	int fd = getsocket();
    enum app_tag tag = CME_CMH_REQUEST;
    if(write(fd,&tag,sizeof(tag)) != sizeof(tag)){
        ERROR_PRINTF("写入失败");
        close(fd);
        return -1;
    }

	int slen = 0;
	int len = 4 + sizeof(cmh);
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		close(fd);
        return -1;
	}
	char* buf_beg = buf;

	int len_r;
    while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            free(buf_beg);
			close(fd);
            return -1;
		}
		slen += len_r;
	}
    if(*((int*)buf) != 0){
        ERROR_PRINTF("B端函数调用失败");
        free(buf_beg);
        close(fd);
        return -1;
    }

    slen = 0;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
			free(buf_beg);
			close(fd);
            return -1;
		}
		slen += len_r;
	}
	len = *((int*)buf);
	slen = 0;
	buf +=4;

	while(slen != len){
		len_r = read(fd,buf+slen,len-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
			free(buf_beg);
			close(fd);
            return -1;
		}
		slen += len_r;
	}

	if(cmh != NULL){
		memcpy(cmh,buf,len);
	}

	free(buf_beg);
	close(fd);
    return 0;
}

/**
 *请求生成一对密钥，
 *@cmh:cme_cmh_request 产生的cmh
 *@pk_algorithm:这对密钥的相关算法
 *@pub_key_x/pub_key_y/pri_key:存放结果的buf，上层得分配好空间。
 *@x_len/y_len/pri_len:在调用的时候里面存放分配的buf的空间有多大，返回的时候里面存放的是填写了多少字节
 *@return 0成功 -1失败
 */

int cme_generate_keypair(cmh cmh,int algorithm,

						char* pub_key_x,int* x_len,
						char* pub_key_y,int* y_len)
{
	if(algorithm<0 || (algorithm>2 && algorithm != 255)){
		ERROR_PRINTF("算法错误");
        return -1;
	}

	int len = 4 + sizeof(app_tag) + sizeof(int) + sizeof(cmh);
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
        return -1;
	}
	char* buf_beg = buf;

    app_tag tag = CME_GENERATE_KEYPARI;
	memcpy(buf,&tag,sizeof(tag));
	buf += sizeof(app_tag);
	
	*((int*)buf) = len - 4 - sizeof(app_tag);
	buf += 4;

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

	*((int*)buf) = algorithm;
	buf += 4;

	int fd = getsocket();
	if( write(fd,buf_beg,len) != len){ //判断写入是否成功
		ERROR_PRINTF("写入失败");
		free(buf_beg);
		close(fd);
        return -1;
	}
	free(buf_beg);

	//新申请一个buf用来存储返回的数据流
	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		close(fd);
        return -1;
	}
	buf_beg = buf;

	int len_r;
    while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            free(buf_beg);
            close(fd);
            return -1;
		}
		slen += len_r;
	}
    if(*((int*)buf) != 0){
        ERROR_PRINTF("B端函数调用失败");
        free(buf_beg);
        close(fd);
        return -1;
    }

    slen=0;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);//返回读取了多少字节，若不够则需要继续读取
		if(len_r <= 0){
			ERROR_PRINTF("读取失败");
			free(buf_beg);
			close(fd);
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
			close(fd);
            return -1;
		}
		slen += len_r;
	}

	slen = *((int*)buf);
    if(x_len != NULL){
		if(*x_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			close(fd);
            return -1;
		}
	    *x_len = slen;
    }
	buf += 4;

	if(pub_key_x != NULL && x_len != NULL){
		memcpy(pub_key_x,buf,slen);
	}
	buf += slen;

	slen = *((int*)buf);
	if(y_len != NULL){
		if(*y_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			close(fd);
            return -1;
		}
		*y_len = slen;
	}
	buf += 4;

	if(pub_key_y != NULL && y_len != NULL)
		memcpy(pub_key_y,buf,slen);

	free(buf_beg);
	close(fd);
    return 0;
}

/**在cmh存储一对密钥
 *@cmh：cme_cmh_request 产生的cmh
 *@pk_algorithm:这对密钥的相关算法
 *@pub_key_x/pub_key_y/pri_key:存放的buf。
 *@x_len/y_len/pri_len:对应buf里面有多少字节。
 *@return 0成功 -1失败
 */

int cme_store_keypair(cmh cmh,int algorithm,
						char* pub_key_x,int x_len,
						char* pub_key_y,int y_len,
						char* pri_key,int pri_len)
{
	if(algorithm<0 || (algorithm>2 && algorithm != 255) ||
		pub_key_x == NULL || pub_key_y == NULL || pri_key == NULL){
		ERROR_PRINTF("参数错误");
		return -1;
	}
	
	int len = 4 + sizeof(app_tag) + sizeof(int)*4 + x_len + y_len + pri_len;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
        return -1;
	}
	char* buf_beg = buf;

    app_tag tag = CME_STORE_KEYPAIR;
	memcpy(buf,&tag,sizeof(app_tag));
	buf += sizeof(app_tag);
	
	*((int*)buf) = len - 4 - sizeof(app_tag);
	buf += 4;

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

	*((int*)buf) = algorithm;
	buf += 4;

	*((int*)buf) = x_len;
	buf += 4;

	memcpy(buf,pub_key_x,x_len);
	buf += x_len;

	*((int*)buf) = y_len;
	buf += 4;

	memcpy(buf,pub_key_y,y_len);
	buf += y_len;

	*((int*)buf) = pri_len;
	buf += 4;

	memcpy(buf,pri_key,pri_len);

    int fd = getsocket();
    if(write(fd,buf_beg,len) != len){
        ERROR_PRINTF("写入失败");
        free(buf_beg);
        close(fd);
        return -1;
    }
	free(buf_beg);

    buf = (char*)malloc(sizeof(int));
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        close(fd);
        return -1;
    }
    int slen = 0;
    int len_r;
    while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            free(buf);
			close(fd);
            return -1;
		}
		slen += len_r;
	}
    if(*((int*)buf) != 0){
        ERROR_PRINTF("B端函数调用失败");
        free(buf);
        close(fd);
        return -1;
    }

    free(buf);
    close(fd);
    return 0;
}


int cme_store_cert(cmh cmh,char* cert,int cert_len,
					char* transfor,int transfor_len)
{
	if(cert == NULL || transfor == NULL){
		ERROR_PRINTF("参数错误");
		return -1;
	}

	int len = 4 + sizeof(app_tag) + sizeof(cmh) + sizeof(int)*2 + cert_len + transfor_len;
	char* buf = (char*)malloc(len);
    app_tag tag = CME_STORE_CERT;
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
        return -1;
	}
	char* buf_beg = buf;

	memcpy(buf,&tag,sizeof(app_tag));
	buf += sizeof(app_tag);

	*((int*)buf) = len - 4 - sizeof(app_tag);
    buf += 4;

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

    *((int*)buf) = cert_len;
    buf += 4;

    memcpy(buf,cert,cert_len);
    buf += cert_len;

	*((int*)buf) = transfor_len;
	buf += 4;

	memcpy(buf,transfor,transfor_len);

	int fd = getsocket();
	if(write(fd,buf_beg,len) != len){
		ERROR_PRINTF("写入失败");
		free(buf_beg);
		close(fd);
        return -1;
	}
	free(buf_beg);

    buf = (char*)malloc(sizeof(int));
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        close(fd);
        return -1;
    }
    int slen = 0;
    int len_r;
    while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            free(buf);
			close(fd);
            return -1;
		}
		slen += len_r;
	}
    if(*((int*)buf) != 0){
        ERROR_PRINTF("B端函数调用失败");
        free(buf);
        close(fd);
        return -1;
    }

    free(buf);
	close(fd);
    return 0;
}

int cme_store_cert_key(cmh cmh,char* cert,int cert_len,
					char* pri_key,int pri_len)
{
	if(cert == NULL || pri_key == NULL){
		ERROR_PRINTF("参数错误");
		return -1;
	}

	int len = 4 + sizeof(app_tag) + sizeof(cmh) + sizeof(int)*2 + cert_len + pri_len;
	char* buf = (char*)malloc(len);
    app_tag tag = CME_STORE_CERT_KEY;
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
        return -1;
	}
	char* buf_beg = buf;

	memcpy(buf,&tag,sizeof(app_tag));
	buf += sizeof(app_tag);
	
    *((int*)buf) = len - 4 - sizeof(app_tag);
	buf += 4;
							
	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

    *((int*)buf) = cert_len;
    buf += 4;

    memcpy(buf,cert,cert_len);
    buf += cert_len;

	*((int*)buf) = pri_len;
	buf += 4;

	memcpy(buf,pri_key,pri_len);

	int fd = getsocket();
	if(write(fd,buf_beg,len) != len){
		ERROR_PRINTF("写入失败");
		free(buf_beg);
		close(fd);
        return -1;
	}
	free(buf_beg);

    buf = (char*)malloc(sizeof(int));
    if(buf == NULL){
        ERROR_PRINTF("内存分配失败");
        close(fd);
        return -1;
    }
    int slen = 0;
    int len_r;
    while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            perror("read");
            free(buf);
			close(fd);
            return -1;
		}
		slen += len_r;
	}
    if(*((int*)buf) != 0){
        ERROR_PRINTF("B端函数调用失败");
        free(buf);
        close(fd);
        return -1;
    }

    free(buf);
	close(fd);
    return 0;
}

/**
 *@set_geneartion_time/set_generation_location/set_expiry_time/compressed:只能为0或1
 *@elevation:这个我们默认只有两字节，我们自动往后读两字节，
 *@*type:各种type的画，请核实下相关结构题里面的值，只能取这些值。
 */
int sec_signed_data(cmh cmh,int type,char* data,int data_len,char* exter_data,int exter_len,psid psid,
					char* ssp,int ssp_len,int set_generation_time,
					time64 generation_time,unsigned char generation_long_std_dev,
					int set_generation_location,int latitude,int longtitude,unsigned char *elevation,
					int set_expiry_time,time64 expiry_time,int signer_type,int cert_chain_len,
					unsigned int cert_chain_max_len,int fs_type,int compressed,
					
					char* signed_data,int* signed_data_len,int *len_of_cert_chain)
{
	if((set_generation_time != 0 && set_generation_time !=1) ||
		(set_generation_location != 0 && set_generation_location != 1) ||
		(set_expiry_time != 0 && set_expiry_time != 1) ||
		(compressed != 0 && compressed != 1) ||
        (type <0 || type >12) ||
		(signer_type < 0 || signer_type > 2) ||
		(fs_type < 0 || fs_type > 2) ||
		data == NULL || elevation == NULL)
	{
		ERROR_PRINTF("参数错误");
        return -1;
	}
    printf("psid: %04x\n",psid);
	int len = 4 + sizeof(app_tag) + sizeof(int)*14 + sizeof(cmh) + sizeof(psid) + sizeof(time64)*2
				+ 3 + data_len + exter_len + ssp_len;
	char* buf = (char*)malloc(len);
    app_tag tag = SEC_SIGNED_DATA;
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
        return -1;
	}
	char* buf_beg = buf;

	memcpy(buf,&tag,sizeof(app_tag));
	buf += sizeof(app_tag);

	*((int*)buf) = len - 4 - sizeof(app_tag);
	buf += 4;

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

	*((int*)buf) = type;
	buf += 4;

	*((int*)buf) = data_len;
	buf += 4;

	memcpy(buf,data,data_len);
	buf += data_len;

	*((int*)buf) = exter_len; //exter_data可能为NULL
	buf += 4;

    if(exter_len != 0){ 
        memcpy(buf,exter_data,exter_len);
        buf += exter_len;
    }

	*((typeof(psid)*)buf) = psid;
	buf += sizeof(psid);

	*((int*)buf) = ssp_len;
	buf += 4;

    if(ssp_len != 0){
        memcpy(buf,ssp,ssp_len);
        buf += ssp_len;
    }

	*((int*)buf) = set_generation_time;
	buf += 4;

	memcpy(buf,&generation_time,sizeof(time64));
	buf += sizeof(time64);

	*buf++ = generation_long_std_dev;

	*((int*)buf) = set_generation_location;
	buf += 4;

	*((int*)buf) = latitude;
	buf += 4;

	*((int*)buf) = longtitude;
	buf += 4;

	memcpy(buf,elevation,2);
	buf += 2;

	*((int*)buf) = set_expiry_time;
	buf += 4;

	memcpy(buf,&expiry_time,sizeof(expiry_time));
	buf += sizeof(time64);

	*((int*)buf) = signer_type;
	buf += 4;

	*((int*)buf) = cert_chain_len;
	buf += 4;

	*((int*)buf) = cert_chain_max_len;
	buf += 4;

	*((int*)buf) = fs_type;
	buf += 4;

	*((int*)buf) = compressed;
	buf += 4;

	int fd = getsocket();
	if(write(fd,buf_beg,len) != len){
		ERROR_PRINTF("写入失败");
		free(buf_beg);
		close(fd);
        return -1;
	}
	free(buf_beg);

	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		close(fd);
        return -1;
	}
	buf_beg = buf;

	int len_r;
    while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            free(buf_beg);
			close(fd);
            return -1;
		}
		slen += len_r;
	}
    if(*((int*)buf) != 0){
        ERROR_PRINTF("B端函数调用失败");
        free(buf_beg);
        close(fd);
        return -1;
    }

    slen=0;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取失败");
			free(buf_beg);
			close(fd);
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
			close(fd);
            return -1;
		}
		slen += len_r;
	}

	slen = *((int*)buf);
	if(signed_data_len != NULL){
		if(*signed_data_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			close(fd);
            return -1;
		}
		*signed_data_len = slen;
	}
	buf += 4;

	if(signed_data != NULL)
		memcpy(signed_data,buf,slen);
	buf += slen;

	if(len_of_cert_chain != NULL)
		*len_of_cert_chain = *((int*)buf);

	free(buf_beg);
	close(fd);
    return 0;
}



/**
 * @compressed:这能为0或者1
 */
int sec_encrypted_data(int type,char* data,int data_len,char* certs,int certs_len,int certs_data_len,int compressed,time64 time,
		        
						char* encrypted_data,int *encrypted_len,char* failed_certs,int *failed_certs_len,int *failed_certs_data_len)
{
	if((compressed != 0 && compressed != 1) ||
		(type < 0 || type > 12) ||
		data == NULL || certs == NULL)
	{
		ERROR_PRINTF("参数错误");
        return -1;
	}

	int len = 4 + sizeof(app_tag) + sizeof(int)*5 + sizeof(time64) + data_len + certs_data_len;
    app_tag tag = SEC_ENCRYPTED_DATA;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
        return -1;
	}
	char* buf_beg = buf;

	memcpy(buf,&tag,sizeof(app_tag));
	buf += sizeof(app_tag);

    *((int*)buf) = len - 4 - sizeof(app_tag);
    buf += 4;

	*((int*)buf) = type;
	buf += 4;

	*((int*)buf) = data_len;
	buf += 4;

	memcpy(buf,data,data_len);
	buf += data_len;

	*((int*)buf) = certs_len;  //证书链中证书的个数
	buf += 4;

    *((int*)buf) = certs_data_len;  //证书链的总数据长度
    buf += 4;

    memcpy(buf,certs,certs_data_len);
    buf += certs_data_len;

	*((int*)buf) = compressed;
	buf += 4;

	memcpy(buf,&time,sizeof(time64));
	buf += sizeof(time64);

	int fd = getsocket();
	if(write(fd,buf_beg,len) != len){
		ERROR_PRINTF("写入失败");
		free(buf_beg);
		close(fd);
        return -1;
	}
	free(buf_beg);

	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		close(fd);
        return -1;
	}
	buf_beg = buf;

	int len_r;
    while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            free(buf_beg);
			close(fd);
            return -1;
		}
		slen += len_r;
	}
    if(*((int*)buf) != 0){
        ERROR_PRINTF("B端函数调用失败");
        free(buf_beg);
        close(fd);
        return -1;
    }

    slen=0;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
			free(buf_beg);
			close(fd);
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
			close(fd);
            return -1;
		}
		slen += len_r;
	}

	slen = *((int*)buf);
	if(encrypted_len != NULL){
		if(*encrypted_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			close(fd);
            return -1;
		}
		*encrypted_len = slen;
	}
	buf += 4;

	if(encrypted_data != NULL)
		memcpy(encrypted_data,buf,*encrypted_len);
	buf += slen;

	slen = *((int*)buf);
	if(failed_certs_len != NULL){
		if(*failed_certs_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			close(fd);
            return -1;
		}
		*failed_certs_len = slen;
	}
	buf += 4;

    if(failed_certs_data_len != NULL){
        *failed_certs_data_len = *((int*)buf);
    }
    buf += 4;

    if(failed_certs != NULL && failed_certs_len != NULL && failed_certs_data_len != NULL){
        memcpy(failed_certs,buf,*failed_certs_data_len);
    }

	free(buf_beg);
	close(fd);
    return 0;
}

/**
 *@set_geneartion_time/set_generation_location:只能为0或者1
 *@elevation:默认是两字节，只能为两字节
 */
int sec_secure_data_content_extration(char* recieve_data,int recieve_len,cmh cmh,
		        
				int *type,int *inner_type,char* data,int* data_len,char* signed_data,int* signed_len,
				psid* pid,char* ssp,int *ssp_len,int *set_generation_time,time64* generation_time,
				unsigned char *generation_long_std_dev,int* set_expiry_time,time64* expiry_time,
                int *set_generation_location,int* latitude,int* longtitude,
				unsigned char *elevation,char* send_cert,int* cert_len)
{
	if(recieve_data == NULL){
		ERROR_PRINTF("参数错误");
		return -1;
	}

	int len = 4 + sizeof(app_tag) + sizeof(int) + sizeof(cmh) + recieve_len;
	char* buf = (char*)malloc(len);
    app_tag tag = SEC_SECURE_DATA_CONTENT_EXTRATION;
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;
    
	memcpy(buf,&tag,sizeof(app_tag));
	buf += sizeof(app_tag);
	
	*((int*)buf) = len - 4 - sizeof(app_tag);
	buf += 4;

	*((int*)buf) = recieve_len;
	buf += 4;

	memcpy(buf,recieve_data,recieve_len);
	buf += recieve_len;

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

	int fd = getsocket();
	if(write(fd,buf_beg,len) != len){
		ERROR_PRINTF("写入失败");
		free(buf_beg);
		close(fd);
        return -1;
	}
	free(buf_beg);

	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		close(fd);
        return -1;
	}
	buf_beg = buf;
	int len_r;
    while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            free(buf_beg);
			close(fd);
            return -1;
		}
		slen += len_r;
	}
    if(*((int*)buf) != 0){
        ERROR_PRINTF("B端函数调用失败");
        free(buf_beg);
        close(fd);
        return -1;
    }

    slen=0;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
			free(buf_beg);
			close(fd);
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
			close(fd);
            return -1;
		}
		slen += len_r;
	}

	if(type != NULL)
		*type = *((int*)buf);
	buf += 4;

	if(inner_type != NULL)
		*inner_type = *((int*)buf);
	buf += 4;

	slen = *((int*)buf);
	if(data_len != NULL){
		if(*data_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			close(fd);
            return -1;
		}
		*data_len = slen;
	}
	buf += 4;

	if(data != NULL)
		memcpy(data,buf,slen);
	buf += slen;

	slen = *((int*)buf);
	if(signed_len != NULL){
		if(*signed_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			close(fd);
            return -1;
		}
		*signed_len = slen;
	}
	buf += 4;

	if(signed_data != NULL)
		memcpy(signed_data,buf,slen);
	buf += slen;

	if(pid != NULL)
		*pid = *((psid*)buf);
	buf += sizeof(psid);

	slen = *((int*)buf);
	if(ssp_len != NULL){
		if(*ssp_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			close(fd);
            return -1;
		}
		*ssp_len = slen;
	}
	buf += 4;

	if(ssp != NULL)
		memcpy(ssp,buf,slen);
	buf += slen;

	if(set_generation_time != NULL)
		*set_generation_time = *((int*)buf);
	buf += 4;

	if(generation_time != NULL)
		memcpy(generation_time,buf,sizeof(time64));
	buf += sizeof(time64);

	if(generation_long_std_dev != NULL)
		*generation_long_std_dev = *buf++;

    if(set_expiry_time != NULL)
        *set_expiry_time = *((int*)buf);
    buf += 4;

    if(expiry_time != NULL)
        memcpy(expiry_time,buf,sizeof(time64));
    buf += sizeof(time64);

	if(set_generation_location != NULL)
		*set_generation_location = *((int*)buf);
	buf += 4;

	if(latitude != NULL)
		*latitude = *((int*)buf);
	buf += 4;

	if(longtitude != NULL)
		*longtitude = *((int*)buf);
	buf += 4;

	if(elevation != NULL)
		memcpy(elevation,buf,2);
	buf += 2;

    slen = *((int*)buf);
    buf += 4;
    if(cert_len != NULL){
        if(*cert_len < slen){
            ERROR_PRINTF("分配空间不足");
            free(buf_beg);
            close(fd);
            return -1;
        }
        *cert_len = slen;
    }

    if(send_cert != NULL){
        memcpy(send_cert,buf,slen);
    }
	
	free(buf_beg);
	close(fd);
    printf("sec_secure_extration success %s %d\n",__FILE__,__LINE__);
    return 0;
}


/**
 *@detect_reply/check_generation_time/check_expiry_time/check_generation_location:只能为0或这1
 *@elevation:默认为2字节。
 */
int sec_signed_data_verification(cme_lsis lsis,psid psid,int  type,
		        char* signed_data,int signed_len,
				char* external_data,int external_len,
				int  max_cert_chain_len,
				int detect_reply,
				int check_generation_time,
				time64 validity_period,
				time64 generation_time,
				unsigned char long_std_dev,
				float generation_threshold,
				time64 accepte_time,
				float accepte_threshold,
				int check_expiry_time,
				time64 expiry_time,
				float exprity_threshold,
				int check_generation_location,
				int latitude,int longtitude,
				unsigned int  validity_distance,
				int generation_latitude, 
				int generation_longtitude,
				unsigned char* elevation,
				time64 overdue_crl_tolerance,
				
				time32 *last_recieve_crl_times,int *last_len,
				time32 *next_expected_crl_times,int *next_len,
				char* send_cert,int* cert_len){

	if((detect_reply != 0 && detect_reply != 1) ||
		(check_generation_time != 0 && check_generation_time != 1) ||
		(check_expiry_time != 0 && check_expiry_time != 1) ||
		(check_generation_location != 0 && check_generation_location != 1) ||
		signed_data == NULL || elevation == NULL)
	{
		ERROR_PRINTF("参数错误");
		return -1;
	}

	int len = 4 + sizeof(app_tag) + sizeof(int)*13 + sizeof(float)*3 + sizeof(psid) + sizeof(time64)*5
				+ 3 + sizeof(lsis) + signed_len + external_len;
	char* buf = (char*)malloc(len);
    app_tag  tag = SEC_SIGNED_DATA_VERIFICATION;
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	memcpy(buf,&tag,sizeof(app_tag));
	buf += sizeof(app_tag);

	*((int*)buf) = len - 4 - sizeof(app_tag);
	buf += 4;

	memcpy(buf,&lsis,sizeof(lsis));
	buf += sizeof(lsis);

	*((int*)buf) = psid;
	buf += 4;

	*((int*)buf) = type;
	buf += 4;

	*((int*)buf) = signed_len;
	buf += 4;

	memcpy(buf,signed_data,signed_len);
	buf += signed_len;

	*((int*)buf) = external_len;
	buf += 4;

    if(external_len != 0){
        memcpy(buf,external_data,external_len);
        buf += external_len;
    }

	*((int*)buf) = max_cert_chain_len;
	buf += 4;

	*((int*)buf) = detect_reply;
	buf += 4;

	*((int*)buf) = check_generation_time;
	buf += 4;

	memcpy(buf,&validity_period,sizeof(time64));
	buf += sizeof(time64);

	memcpy(buf,&generation_time,sizeof(time64));
	buf += sizeof(time64);

	*buf++ = long_std_dev;

	*((float*)buf) = generation_threshold;
	buf += 4;

	memcpy(buf,&accepte_time,sizeof(time64));
	buf += sizeof(time64);

	*((float*)buf) = accepte_threshold;
	buf += 4;

	*((int*)buf) = check_expiry_time;
	buf += 8;

    printf("expiry time: %llu %s %d\n",expiry_time,__FILE__,__LINE__);
	memcpy(buf,&expiry_time,sizeof(time64));
	buf += sizeof(time64);

	*((float*)buf) = exprity_threshold;
	buf += 4;

	*((int*)buf) = check_generation_location;
	buf += 4;

	*((int*)buf) = latitude;
	buf += 4;

	*((int*)buf) = longtitude;
	buf += 4;

	*((int*)buf) = validity_distance;
	buf += 4;

	*((int*)buf) = generation_latitude;
	buf += 4;

	*((int*)buf) = generation_longtitude;
	buf += 4;

	memcpy(buf,elevation,2);
	buf += 2;

	memcpy(buf,&overdue_crl_tolerance,sizeof(time64));
	buf += sizeof(time64);

	int fd = getsocket();
	if(write(fd,buf_beg,len) != len){
		ERROR_PRINTF("写入失败");
		free(buf_beg);
		close(fd);
        return -1;
	}
	free(buf_beg);

	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		close(fd);
        return -1;	
    }
	buf_beg = buf;

	int len_r;
    while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
            free(buf_beg);
			close(fd);
            return -1;
		}
		slen += len_r;
	}
    if(*((int*)buf) != 0){
        ERROR_PRINTF("B端函数调用失败");
        free(buf_beg);
        close(fd);
        return -1;
    }

    slen=0;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
			free(buf_beg);
			close(fd);
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
			close(fd);
            return -1;
		}
		slen += len_r;
	}

	slen = *((int*)buf);
	if(last_len != NULL){
		if(*last_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			close(fd);
            return -1;
		}
		*last_len = slen;
	}
	buf += 4;

	if(last_recieve_crl_times != NULL && last_len != NULL)
        memcpy(last_recieve_crl_times,buf,sizeof(time32)*(*last_len));
	buf += sizeof(time32)*(*last_len);

	slen = *((int*)buf);
	if(next_len != NULL){
		if(*next_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			close(fd);   
            return -1;
        }
		*next_len = slen;
	}
	buf += 4;

	if(next_expected_crl_times != NULL && next_len != NULL)
        memcpy(next_expected_crl_times,buf,sizeof(time32)*(*next_len));
	buf += sizeof(time32)*(*next_len);

    slen = *((int*)buf);
    buf += 4;
    if(cert_len != NULL){
        if(*cert_len < slen){
            ERROR_PRINTF("分配空间不足");
            free(buf_beg);
            close(buf_beg);
            return -1;
        }
        *cert_len = slen;
    }

    if(send_cert != NULL && cert_len != NULL){
        memcpy(send_cert,buf,slen);
    }

	free(buf_beg);
	close(fd);
    return 0;
}


