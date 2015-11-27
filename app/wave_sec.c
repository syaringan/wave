#include<stdio.h>
#include<string.h>
#include<stdlib.h>
//#include"wave_sec.h"

#include "../utils/list.h"
#include<pthread.h>
#include<stddef.h>
#include"../utils/af_unix.h"

#define SERVICE "/var/tmp/wave_sec.socket"

#define	ERROR_PRINTF(n) printf("n %s %d",__FILE__,__LINE__)


static struct list_head head ={
    .next = &head,
    .prev = &head,
};//我们用链表实现我们的map
struct map{
    struct list_head list;
    int fd;
    pthread_t tid;
};
static void socket_close(void *ptr){
    struct map *map;
    pthread_t tid;
    tid = pthread_self();

    list_for_each_entry(map,&head,list){
        if(map->tid == tid){
            break;
        }
    }
    if(&map->list != &head){
        list_del(&map->list);
        free(map);
    }
    close(map->fd);
}
static int getsocket(){
    struct list_head *node;
    struct map *map,*new = NULL;
    int fd = -1;
    pthread_t tid;
    tid = pthread_self();
    list_for_each_entry(map,&head,list){
        if(map->tid == tid){
            return fd;
        }
    }
    if( (fd = cli_connect(SERVICE)) < 0){
        goto fail;
    }
    if( (new = (struct map*)malloc(sizeof(struct map))) == NULL){
        wave_malloc_error();
        goto fail;
    }
    new->fd = fd;
    new->tid = tid;
    list_add_tail(new,&head);
    pthread_cleanup_push(socket_close,NULL);
    return fd;
fail:
    if(fd > 0)
        close(fd);
    if(new != NULL)
        free(new);
    return -1;
}


int cme_lsis_request(cme_lsis* lsis){
	int fd = getsocket();
    if(write(fd,&CME_LSIS_REQUEST,sizeof(app_tag)) != sizeof(app_tag)){
        ERROR_PRINTF("写入失败");
        return -1;
    }

	int slen = 0;
	int len = 32;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	int len_r;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
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
			return -1;
		}
		slen += len_r;
	}

	if(lsis != NULL){
		memcpy(lsis,buf,len);
	}

	free(buf_beg);
	return 0;
}

int cme_cmh_request(cmh* cmh){
	int fd = getsocket();
    if(write(fd,&CME_CMH_REQUEST,sizeof(app_tag)) != sizeof(app_tag)){
        ERROR_PRINTF("写入失败");
        return -1;
    }

	int slen = 0;
	int len = 32;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	int len_r;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
			free(buf_beg);
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
			return -1;
		}
		slen += len_r;
	}

	if(lsis != NULL){
		memcpy(cmh,buf,len);
	}

	free(buf_beg);
	return 0;
}

int cme_generate_keypair(cmh cmh,int algorithm,

						char* pub_key_x,int* x_len,
						char* pub_key_y,int* y_len,
						char* pri_key,int* pri_len)
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

	memcpy(buf,&CME_GENERATE_KEYPARI,sizeof(app_tag));
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
		return -1;
	}
	free(buf_beg);

	//新申请一个buf用来存储返回的数据流
	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	buf_beg = buf;

	int len_r;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);//返回读取了多少字节，若不够则需要继续读取
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

	slen = *((int*)buf);
    if(x_len != NULL){
		if(*x_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
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
			return -1;
		}
		*y_len = slen;
	}
	buf += 4;

	if(pub_key_y != NULL && y_len != NULL)
		memcpy(pub_key_y,buf,slen);
	buf += slen;

	slen = *((int*)buf);
	if(pri_len != NULL){
		if(*pri_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			return -1;
		}
		*pri_len = slen;
	}
	buf += 4;

	if(pri_key != NULL && pri_len != NULL)
		memcpy(pri_key,buf,slen);

	free(buf_beg);
	return 0;
}
//???????????????
int cme_store_keypair(cmh cmh,int algorithm,
						char* pub_key_x,int x_len,
						char* pub_key_y,int y_len,
						char* pri_key,int pri_len)
{
	if(algorithm<0 || (algorithm>2 && algorithm != 255)){
		ERROR_PRINTF("算法错误");
		return -1;
	}
	
	int len = 4 + sizeof(app_tag) + sizeof(int)*4 + x_len + y_len + pri_len; //app_tag??
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	//  没有tag??
	
	*((int*)buf) = len - 4 - sizeof(app_tag);  //app_tag?
	buf += 4;

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

	*((int*)buf) = algorithm;
	buf += 4;

	*((int*)buf) = x_len;
	buf += 4;

	if(pub_key_x != NULL)  //NULL直接跳过?
		memcpy(buf,pub_key_x,x_len);
	buf += x_len;

	*((int*)buf) = y_len;
	buf += 4;

	if(pub_key_y != NULL)
		memcpy(buf,pub_key_y,y_len);
	buf += y_len;

	*((int*)buf) = pri_len;
	buf += 4;

	if(pri_key != NULL)
		memcpy(buf,pri_key,pri_len);

	free(buf_beg);
	return 0;
}




int cme_store_cert(cmh cmh,certificate* cert,
					char* transfor,int transfor_len)
{
	int len = 1024;
	int count = 0;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	memcpy(buf,&CME_STORE_CERT,sizeof(app_tag));
	buf += sizeof(app_tag);
	count += sizeof(app_tag);

	buf += 4;
	count += 4; //后面计算长度时-4

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);
	count += sizeof(cmh);

	char* cert_len_p = buf; //空1字节保存cert的长度
	buf += 4;
	count += 4;
	
	if(cert != NULL){
		int cert_len = -2;
		while(cert_len == -2){ //buf空间不足
			cert_len = certificate_2_buf(cert,buf,len-count);
			if(cert_len == -1){
				ERROR_PRINTF("certificate_2_buf失败");
				free(buf_beg);
				return -1;
			}else if(cert_len == -2){
				len *= 2;
				buf_beg = (char*)realloc(buf_beg,len);
				cert_len_p = buf_beg + count - 4;
				buf = buf_beg + count;
			}
		}
		*cert_len_p = cert_len;
		buf += cert_len;
		count += cert_len;
	}else{
		*cert_len_p = 0;  //cert为空，将长度置为0
	}

	if(len < (count + transfor_len + 4)){
		buf_beg = (char*)realloc(buf_beg,count + transfor_len + 4);
		buf = buf_beg + count;
	}

	*((int*)buf) = transfor_len;
	buf += 4;
	count += 4;

	if(transfor != NULL)
		memcpy(buf,transfor,transfor_len);
	count += transfor_len;

	*((int*)(buf_beg+sizeof(app_tag))) = count - 4 - sizeof(app_tag); //在app_tag后填充数据长度

	int fd = getsocket();
	if(write(fd,buf_beg,count) != count){
		ERROR_PRINTF("写入失败");
		free(buf_beg);
		return -1;
	}

	free(buf_beg);
	return 0;
}

int cme_store_cert_key(cmh cmh,certificate* cert,
					char* pri_key,int pri_len)
{
	int len = 1024;
	int count = 0;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	memcpy(buf,&CME_STORE_CERT_KEY,sizeof(app_tag));
	buf += sizeof(app_tag);
	count += sizeof(app_tag);
				
	buf += 4;
	count += 4;
							
	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);
	count += sizeof(cmh);
										
	char* cert_len_p = buf;
	buf += 4;
	count += 4;

	if(cert != NULL){
		int cert_len = -2;
		while(cert_len == -2){
			cert_len = certificate_2_buf(cert,buf,len-count);
			if(cert_len == -1){
				ERROR_PRINTF("certificate_2_buf失败");
				free(buf_beg);
				return -1;
			}else if(cert_len == -2){
				len *= 2;
				buf_beg = (char*)realloc(buf_beg,len);
				cert_len_p = buf_beg + count - 4;
				buf = buf_beg + count;
			}
		}
		*cert_len_p = cert_len;
		buf += cert_len;
		count += cert_len;
	}else{
		*cert_len_p = 0;
	}

	if(len < (count + pri_len + 4)){
		buf_beg = (char*)realloc(buf_beg,count + pri_len + 4);
		buf = buf_beg + count;
	}

	*((int*)buf) = pri_len;
	buf += 4;
	count += 4;

	if(pri_key != NULL)
		memcpy(buf,pri_key,pri_len);
	count += pri_len;

	*((int*)(buf_beg+sizeof(app_tag))) = count - 4 - sizeof(app_tag);

	int fd = getsocket();
	if(write(fd,buf_beg,count) != count){
		ERROR_PRINTF("写入失败");
		free(buf_beg);
		return -1;
	}

	free(buf_beg);
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
	if((set_geneartion_time != 0 && set_geneartion_time !=1) ||
		(set_generation_location != 0 && set_generation_location != 1) ||
		(set_expiry_time != 0 && set_expiry_time != 1) ||
		(compressed != 0 && compressed != 1) ||
        (type <0 || type >12) ||
		(signer_type < 0 || signer_type > 2) ||
		(fs_type < 0 || fs_type > 2) )
	{
		ERROR_PRINTF("参数错误");
		return -1;
	}

	int len = 4 + sizeof(app_tag) + sizeof(int)*14 + sizeof(cmh) + sizeof(psid) + sizeof(time64)*2
				+ 3 + data_len + exter_len + ssp_len;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	memcpy(buf,&SEC_SIGNED_DATA,sizeof(app_tag));
	buf += sizeof(app_tag);

	*((int*)buf) = len - 4 - sizeof(app_tag);
	buf += 4;

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

	*((int*)buf) = type;
	buf += 4;

	*((int*)buf) = data_len;
	buf += 4;

	if(data != NULL)
		memcpy(buf,data,data_len);
	buf += data_len;

	*((int*)buf) = exter_len;
	buf += 4;

	if(exter_data != NULL)
		memcpy(buf,exter_data,exter_len);
	buf += exter_len;

	*((psid*)buf) = psid;
	buf += sizeof(psid);

	*((int*)buf) = ssp_len;
	buf += 4;

	if(ssp != NULL)
		memcpy(buf,ssp,ssp_len);
	buf += ssp_len;

	*((int*)buf) = set_geneartion_time;
	buf += 4;

	memcpy(buf,&generation_time,sizeof(time64));
	buf += sizeof(time64);

	*buf++ = generation_long_std_dev;

	*((int*)buf) = set_generation_location;
	buf += 4;

	*((int*)buf) = latitude;
	buf += 4;

	*((int*)buf) = longtitude;
	buf += 4;}

	memcpy(buf,elevation,2);
	buf += 2;

	*((int*)buf) = set_expiry_time;
	buf += 4;

	memcpy(buf,&exprity_time,sizeof(time64));
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
		return -1;
	}
	free(buf_beg);

	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	buf_beg = buf;

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

	slen = *((int*)buf);
	if(signed_data_len != NULL){
		if(*signed_data_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
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
	return 0;
}



/**
 * @compressed:这能为0或者1
 */
int sec_encrypted_data(int type,char* data,int data_len,certificate *certs,int certs_len,int compressed,time64 time,
		        
						char* encrypted_data,int *encrypted_len,certificate *failed_certs,int *failed_certs_len)
{
	if((compressed != 0 && compressed != 1) ||
		(type < 0 || type > 12))
	{
		ERROR_PRINTF("参数错误");
		return -1;
	}

	int len = 4 + sizeof(app_tag) + sizeof(int)*4 + sizeof(time64) + data_len + certs_len;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	memcpy(buf,&SEC_ENCRYPTED_DATA,sizeof(app_tag));
	buf += sizeof(app_tag);

	*((int*)buf) = len - 4 - sizeof(app_tag);
	buf += 4;

	*((int*)buf) = type;
	buf += 4;

	*((int*)buf) = data_len;
	buf += 4;

	if(data != NULL)
		memcpy(buf,data,data_len);
	buf += data_len;

	*((int*)buf) = certs_len;
	buf += 4;

	if(certs != NULL){
		if(certificate_2_buf(certs,buf,certs_len) < 0){
			ERROR_PRINTF("certificate_2_buf失败");
			free(buf_beg);
			return -1;
		}
	}
	buf += certs_len;

	*((int*)buf) = compressed;
	buf += 4;

	memcpy(buf,&time,sizeof(time64));
	buf += sizeof(time64);

	int fd = getsocket();
	if(write(fd,buf_beg,len) != len){
		ERROR_PRINTF("写入失败");
		free(buf_beg);
		return -1;
	}
	free(buf_beg);

	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	buf_beg = buf;

	int len_r;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
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

	slen = *((int*)buf);
	if(encrypted_len != NULL){
		if(*encrypted_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
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
			return -1;
		}
		*failed_certs_len = slen;
	}
	buf += 4;

	if(failed_certs != NULL && failed_certs_len != NULL){
		if(buf_2_certificate(buf,failed_certs_len,failed_certs) < 0){
			ERROR_PRINTF("buf_2_certificate失败");
			free(buf_beg);
			return -1;
		}
	}

	free(buf_beg);
	return 0;
}

/**
 *@set_geneartion_time/set_generation_location:只能为0或者1
 *@elevation:默认是两字节，只能为两字节
 */
int sec_secure_data_content_extration(char* recieve_data,int recieve_len,cmh cmh,
		        
				int *type,int *inner_type,char* data,int* data_len,char* signed_data,int* signed_len,
				psid* psid,char* ssp,int *ssp_len,int *set_generation_time,time64* generation_time,
				unsigned char *generation_long_std_dev,int *set_generation_location,int* latitude,int* longtitude,
				unsigned char *elevation,certificate* send_cert)
{
	int len = 4 + sizeof(app_tag) + sizeof(int) + sizeof(cmh) + recieve_len;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	memcpy(buf,&SEC_SECURE_DATA_CONTENT_EXTRATION,sizeof(app_tag));
	buf += sizeof(app_tag);
	
	*((int*)buf) = len - 4 - sizeof(app_tag);
	buf += 4;

	*((int*)buf) = recieve_len;
	buf += 4;

	if(recieve_data != NULL)
		memcpy(buf,recieve_data,recieve_len);
	buf += recieve_len;

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

	int fd = getsocket();
	if(write(fd,buf_beg,len) != len){
		ERROR_PRINTF("写入失败");
		free(buf_beg);
		return -1;
	}
	free(buf_beg);

	int slen = 0;
	int count = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	buf_beg = buf;
	
	int len_r;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
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

	if(type != NULL)
		*type = *((int*)buf);
	buf += 4;
	count += 4;

	if(inner_type != NULL)
		*inner_type = *((int*)buf);
	buf += 4;
	count += 4;

	slen = *((int*)buf);
	if(data_len != NULL){
		if(*data_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			return -1;
		}
		*data_len = slen;
	}
	buf += 4;
	count += 4;

	if(data != NULL)
		memcpy(data,buf,slen);
	buf += slen;
	count += slen;

	slen = *((int*)buf);
	if(signed_len != NULL){
		if(*signed_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			return -1;
		}
		*signed_len = slen;
	}
	buf += 4;
	count += 4;

	if(signed_data != NULL)
		memcpy(signed_data,buf,slen);
	buf += slen;
	count += slen;

	if(psid != NULL)
		*psid = *((psid*)buf);
	buf += sizeof(psid);
	count += sizeof(psid);

	slen = *((int*)buf);
	if(ssp_len != NULL){
		if(*ssp_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			return -1;
		}
		*ssp_len = slen;
	}
	buf += 4;
	count += 4;

	if(ssp != NULL)
		memcpy(ssp,buf,slen);
	buf += slen;
	count += slen;

	if(set_geneartion_time != NULL)
		*set_geneartion_time = *((int*)buf);
	buf += 4;
	count += 4;

	if(generation_time != NULL)
		memcpy(generation_time,buf,sizeof(time64));
	buf += sizeof(time64);
	count += sizeof(time64);

	if(generation_long_std_dev != NULL)
		*generation_long_std_dev = *buf++;
	count++;

	if(set_generation_location != NULL)
		*set_generation_location = *((int*)buf);
	buf += 4;
	count += 4;

	if(latitude != NULL)
		*latitude = *((int*)buf);
	buf += 4;
	count += 4;

	if(longtitude != NULL)
		*longtitude = *((int*)buf);
	buf += 4;
	count += 4;

	if(elevation != NULL)
		memcpy(elevation,buf,2);
	buf += 2;
	count += 2;

	if(send_cert != NULL){
		if(buf_2_certificate(buf,len-count,send_cert) < 0){
			ERROR_PRINTF("buf_2_certificate失败");
			free(buf_beg);
			return -1;
		}
	}
	
	free(buf_beg);
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
				time64 exprity_time,
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
				certificate* send_cert)
{
	if((detect_reply != 0 && detect_reply != 1) ||
		(check_generation_time != 0 && check_generation_time != 1) ||
		(check_expiry_time != 0 && check_expiry_time != 1) ||
		(check_generation_location != 0 && check_generation_location != 1))
	{
		ERROR_PRINTF("参数错误");
		return -1;
	}

	int len = 4 + sizeof(app_tag) + sizeof(int)*13 + sizeof(float)*3 + sizeof(psid) + sizeof(time64)*5
				+ 3 + sizeof(lsis) + signed_len + external_len;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	memcpy(buf,&SEC_SIGNED_DATA_VERIFICATION,sizeof(app_tag));
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

	if(signed_data != NULL)
		memcpy(buf,signed_data,signed_len);
	buf += signed_len;

	*((int*)buf) = external_len;
	buf += 4;

	if(external_data != NULL)
		memcpy(buf,external_data,external_len);
	buf += external_len;

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
		return -1;
	}
	free(buf_beg);

	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		ERROR_PRINTF("内存分配失败");
		return -1;
	}
	buf_beg = buf;

	int len_r;
	while(slen != 4){
		len_r = read(fd,buf+slen,4-slen);
		if(len_r <= 0){
			ERROR_PRINTF("读取错误");
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

	slen = *((int*)buf);
	if(last_len != NULL){
		if(*last_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			return -1;
		}
		*last_len = slen;
	}
	buf += 4;

	if(last_recieve_crl_times != NULL)
		*last_recieve_crl_times = *((time32*)buf);
	buf += sizeof(time32);

	slen = *((int*)buf);
	if(next_len != NULL){
		if(*next_len < slen){
			ERROR_PRINTF("分配空间不足");
			free(buf_beg);
			return -1;
		}
		*next_len = slen;
	}
	buf += 4;

	if(next_expected_crl_times != NULL)
		*next_expected_crl_times = *((time32*)buf);
	buf += sizeof(time32);

	if(send_cert != NULL){
		if(buf_2_certificate(buf,len-8-sizeof(time32)*2,send_cert) < 0){
			ERROR_PRINTF("buf_2_certificate失败");
			free(buf_beg);
			return -1;
		}
	}
	
	free(buf_beg);
	return 0;
}


