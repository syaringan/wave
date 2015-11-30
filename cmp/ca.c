#include "ca.h"
#include<sys/socket.h>
#include<arpa/inet.h>
#define PORT 6780
#define ADDR "1.1.1.1.1.1"
#define RECIEVE_LEN 1024
static int sockfd;
static struct sockaddr addr;
int ca_init(){
    struct sockaddr_in6 *ip6_ptr;

    sockfd = socket(AF_INET6,SOCK_DGRAM,0);//这里的参数选取不知道对不
    if(sockfd < 0)
        return -1;
    //感觉地址的填写有些字段我都没填写，特别是sin6_len 这个字段，有些书上说我们需要填写？？？
    ip6_ptr = (struct sockaddr_in6*)&addr;
    ip6_ptr->sin6_family = AF_INET6;
    ip6_ptr->sin6_port = htons(PORT);
    if(inet_pton(AF_INET6,ADDR,&ip6_ptr->sin6_addr))
        return -1;
    return 0;
}
int ca_write(string *buf){
    if(buf == NULL || buf->buf != NULL){
        wave_error_printf("参数有问题 %s %d",__FILE__,_LINE__);
        return -1;
    }
    if( sendto(sockfd,buf->buf,buf->len,0,&addr,sizeof(addr)) != buf->len){
        wave_error_printf("发送失败 %s %d",__FILE__,__LINE__);
        return -1;
    }
    return 0;
}
int ca_read(string *buf){
    char *mbuf;
    int readlen;
    if(buf == NULL || buf->buf != NULL){
        wave_error_printf("参数有问题 %s %d",__FILE__,__LINE__);
        return -1;
    }
    
    mbuf = (char*)malloc(RECIEVE_LEN);
    if(mbuf == NULL){
        wave_malloc_error();
        return -1;
    }
    readlen = recvfrom(sockfd,mbuf,RECIEVE_LEN,MSG_TRUNC,NULL,NULL);
    if(readlen > RECIEVE_LEN){
        wave_error_printf("实际的报文大小超过了我们开辟的空间大小 %s %d",__FILE__,__LINE__);
        free(mbuf);
        return -1;
    }
    buf->buf = mbuf;
    buf->len = readlen;
    return 0;
}


