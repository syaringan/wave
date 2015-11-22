#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include"wave_sec.h"

#include "../utils/list.h"
#include<pthread.h>
#include<stddef.h>
#include"../utils/af_unix.h"

#define SERVICE "/var/tmp/wave_sec.socket"

#define PRINTF(n) printf("n %s %d",__FILE__,__LINE__)


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
	int len = sizeof(*lsis);
	int fd = getsocket();
	if(write(fd,lsis,len) != len){
		PRINTF("写入失败");
		return -1;
	}
	return 0;
}

int cme__cmh_request(cmh* cmh){
	int len = sizeof(*cmh);
	int fd = getsocket();
	if(write(fd,cmh,len) != len){
		PRINTF("写入失败");
		return -1;
	}
	return 0;
}

int cme_generate_keypair(cmh cmh,int algorithm,

						char* pub_key_x,int* x_len,
						char* pub_key_y,int* y_len,
						char* pri_key,int* pri_len)
{
	if(algorithm<0 || (algorithm>2 && algorithm<255)){
		PRINTF("算法错误");
		return -1;
	}

	int len = 4*2 + sizeof(cmh);
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;
	
	*((int*)buf) = len;
	buf += 4;

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

	*((int*)buf) = algorithm;
	buf += 4;

	int fd = getsocket();
	if( write(fd,buf_beg,len) != len){ //判断写入是否成功  做了改动，改用len
		PRINTF("写入失败");
		free(buf_beg);
		return -1;
	}
	free(buf_beg);

	//新申请一个buf用来存储返回的数据流
	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	buf_beg = buf;

	while(slen != 4){
		slen += read(fd,buf+slen,4-slen);//返回读取了多少字节，若不够则需要继续读取
	}
	len = *((int*)buf);
	if(len > 1020)
		realloc(buf,len + 4);
	slen = 0;
	buf += 4;

	while(slen != len){  //会不会出现 slen > len 的情况？
		slen += read(fd,buf+slen,len-slen);
	}

	*x_len = *((int*)buf);
	buf += 4;

	memcpy(pub_key_x,buf,*x_len);
	buf += *x_len;

	*y_len = *((int*)buf);
	buf += 4;

	memcpy(pub_key_y,buf,*y_len);
	buf += *y_len;

	*pri_len = *((int*)buf);
	buf += 4;

	memcpy(pri_key,buf,*pri_len);

	free(buf_beg);
	return 0;
}

int cme_store_keypair(cmh cmh,int algorithm,
						char* pub_key_x,int x_len,
						char* pub_key_y,int y_len,
						char* pri_key,int pri_len)
{
	if(algorithm<0 || (algorithm>2 && algorithm<255)){
		PRINTF("算法错误");
		return -1;
	}
	
	int len = 4*5 + sizeof(cmh) + x_len + y_len + pri_len;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;
	
	*((int*)buf) = len;
	buf += 4;

	int i;
	int cmh_length = sizeof(cmh);
	for(i=0;i<cmh_length;i++){
		*buf++ = *((char*)&cmh + i);
	}

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

	free(buf_beg);
	return 0;
}

/*
 *
 * certificate 怎么处理？？
 *
 *
int cme_store_cert(cmh cmh,certificate* cert,int cert_len,
					char* transfor,int transfor_len)
{
	int len = 4*3 + sizeof(cmh) + cert_len + transfor_len;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	*((int*)buf) = len;
	buf += 4;

	int i;
	int cmh_length = sizeof(cmh);
	for(i=0;i<cmh_length;i++)
		*buf++ = *((char*)&cmh + i);

	*((int*)buf) = cert_len;
	buf += 4;

	memcpy(buf,cert,cert_len);
	buf += cert_len;
}

int cme_store_cert_key(cmh cmh,certificate* cert,int cert_len,
					char* pri_key,int pri_len){

}

*/

/**
 *@set_geneartion_time/set_generation_location/set_expiry_time,:只能为0或1
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
		(set_expiry_time != 0 && set_expiry_time != 1))
	{
		PRINTF("参数错误");
		return -1;
	}

	int len = 83 + sizeof(cmh) + data_len + exter_len + ssp_len;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	*((int*)buf) = len;
	buf += 4;

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

	*((int*)buf) = type;
	buf += 4;

	*((int*)buf) = data_len;
	buf += 4;

	memcpy(buf,data,data_len);
	buf += data_len;

	*((int*)buf) = exter_len;
	buf += 4;

	memcpy(buf,exter_data,exter_len);
	buf += exter_len;

	*((int*)buf) = psid;
	buf += 4;

	*((int*)buf) = ssp_len;
	buf += 4;

	memcpy(buf,ssp,ssp_len);
	buf += ssp_len;

	*((int*)buf) = set_geneartion_time;
	buf += 4;

	memcpy(buf,&generation_time,8);
	buf += 8;

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

	memcpy(buf,&exprity_time,8);
	buf += 8;

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
		PRINTF("写入失败");
		free(buf_beg);
		return -1;
	}
	free(buf_beg);

	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	buf_beg = buf;

	while(slen != 4){
		slen += read(fd,buf+slen,4-slen);
	}
	len = *((int*)buf);
	if(len > 1020)
		realloc(buf,len + 4);
	slen = 0;
	buf += 4;

	while(slen != len){
		slen += read(fd,buf+slen,len-slen);
	}

	*signed_data_len = *((int*)buf);
	buf += 4;

	memcpy(signed_data,buf,*signed_data_len);
	buf += *signed_data_len;

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
	if(compressed != 0 && compressed != 1){
		PRINTF("参数错误");
		return -1;
	}

	int len = 28 + data_len + cert_len;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	*((int*)buf) = len;
	buf += 4;

	*((int*)buf) = type;
	buf += 4;

	*((int*)buf) = data_len;
	buf += 4;

	memcpy(buf,data,data_len);
	buf += data_len;

	//certificate这个怎么处理？？

	*((int*)buf) = compressed;
	buf += 4;

	memcpy(buf,&time,8);
	buf += 8;

	int fd = getsocket();
	if(write(fd,buf_beg,len) != len){
		PRINTF("写入失败");
		free(buf_beg);
		return -1;
	}
	free(buf_beg);

	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	buf_beg = buf;

	while(slen != 4){
		slen += read(fd,buf+slen,4-slen);
	}
	len = *((int*)buf);
	if(len > 1020)
		realloc(buf,len + 4);
	slen = 0;
	buf += 4;

	while(slen != len){
		slen += read(fd,buf+slen,len-slen);
	}

	*encrypted_len = *((int*)buf);
	buf += 4;

	//certificate未处理


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
	int len = 8 + sizeof(cmh) + recieve_len;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;
	
	*((int*)buf) = len;
	buf += 4;

	*((int*)buf) = recieve_len;
	buf += 4;

	memcpy(buf,recieve_data,recieve_len);
	buf += recieve_len;

	memcpy(buf,&cmh,sizeof(cmh));
	buf += sizeof(cmh);

	int fd = getsocket();
	if(write(fd,buf_beg,len) != len){
		PRINTF("写入失败");
		free(buf_beg);
		return -1;
	}
	free(buf_beg);

	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	buf_beg = buf;
	
	while(slen != 4){
		slen = read(fd,buf+slen,4-slen);
	}
	len = *((int*)buf);
	if(len > 1020)
		realloc(buf,len + 4);
	slen = 0;
	buf += 4;

	while(slen != len){
		slen += read(fd,buf+slen,len-slen);
	}

	*type = *((int*)buf);
	buf += 4;

	*inner_type = *((int*)buf);
	buf += 4;

	*data_len = *((int*)buf);
	buf += 4;

	memcpy(data,buf,*data_len);
	buf += *data_len;

	*signed_len = *((int*)buf);
	buf += 4;

	memcpy(signed_data,buf,*signed_len);
	buf += *signed_len;

	*psid = *((int*)buf);
	buf += 4;

	*ssp_len = *((int*)buf);
	buf += 4;

	memcpy(ssp,buf,*ssp_len);
	buf += *ssp_len;

	*set_geneartion_time = *((int*)buf);
	buf += 4;

	memcpy(generation_time,buf,8);
	buf += 8;

	*generation_long_std_dev = *buf++;

	*set_generation_location = *((int*)buf);
	buf += 4;

	*latitude = *((int*)buf);
	buf += 4;

	*longtitude = *((int*)buf);
	buf += 4;

	memcpy(elevation,buf,2);
	buf += 2;

	//certificate未处理
	
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
		PRINTF("参数错误");
		return -1;
	}

	int len = 115 + sizeof(lsis) + signed_len + external_len;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;

	*((int*)buf) = len;
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

	memcpy(buf,external_data,external_len);
	buf += external_len;

	*((int*)buf) = max_cert_chain_len;
	buf += 4;

	*((int*)buf) = detect_reply;
	buf += 4;

	*((int*)buf) = check_generation_time;
	buf += 4;

	memcpy(buf,&validity_period,8);
	buf += 8;

	memcpy(buf,&generation_time,8);
	buf += 8;

	*buf++ = long_std_dev;

	*((int*)buf) = generation_threshold;
	buf += 4;

	memcpy(buf,&accepte_time,8);
	buf += 8;

	*((int*)buf) = accepte_threshold;
	buf += 4;

	*((int*)buf) = check_expiry_time;
	buf += 8;

	memcpy(buf,&expiry_time,8);
	buf += 8;

	*((int*)buf) = exprity_threshold;
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

	memcpy(buf,&overdue_crl_tolerance,8);
	buf += 8;

	int fd = getsocket();
	if(write(fd,buf_beg,len) != len){
		PRINTF("写入失败");
		free(buf_beg);
		return -1;
	}
	free(buf_beg);

	int slen = 0;
	len = 1024;
	buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	buf_beg = buf;

	while(slen != 4){
		slen += read(fd,buf+slen,4-slen);
	}
	len = *((int*)buf);
	if(len > 1020)
		realloc(buf,len + 4);
	slen = 0;
	buf += 4;

	while(slen != len){
		slen += read(fd,buf+slen,len-slen);
	}

	//返回参数未处理
	
	free(buf_beg);
	return 0;
}


