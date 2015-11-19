
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
	int count = 0;
	char* buf = (char*)malloc(len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	char* buf_beg = buf;
	buf += 4;

	int i;
	int cmh_length = sizeof(cmh);
	for(i=0;i<cmh_length;i++){
		*buf++ = *((char*)&cmh + i);
	}
	count += cmh_length;

	*((int*)buf) = algorithm;
	buf += 4;
	count += 4;

	buf = buf_beg;
	*((int*)buf) = count;
	count += 4;

	int fd = getsocket();
	if( write(fd,buf_beg,count) != count){ //判断写入是否成功
		PRINTF("写入失败");
		free(buf_beg);
		return -1;
	}
	free(buf_beg);


	//新申请一个buf用来存储返回的数据流
	int slen = 0;
	int data_len = 1024;
	buf = (char*)malloc(data_len);
	if(buf == NULL){
		PRINTF("内存分配失败");
		return -1;
	}
	buf_beg = buf;

	while(slen != 4){
		slen += read(fd,buf+slen,4-slen);//返回读取了多少字节，若不够则需要继续读取
	}
	data_len = *((int*)buf);
	if(data_len > 1020)
		realloc(buf,data_len + 4);
	slen = 0;
	buf += 4;

	while(slen != data_len){  //会不会出现 slen > data_len 的情况？
		slen += read(fd,buf+slen,data_len-slen);
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
