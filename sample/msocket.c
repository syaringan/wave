#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<string.h>
#include<stdio.h>
#define error() printf("erro %s %d\n",__FILE__,__LINE__)
int getsocket(int port){
    int fd;
    struct sockaddr_in addr;
    fd = socket(AF_INET,SOCK_DGRAM,0);
    if(fd < 0){
        error();
        return -1;
    }
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if(bind(fd,(struct sockaddr*)&addr,sizeof(addr))){
        error();
        perror("bind");
        return -1;
    }
    return fd;
}
int msendto(int fd,char* buf,int len,int port){
    struct sockaddr_in addr;
    int mlen;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    mlen = sendto(fd,buf,len,0,(struct sockaddr*)&addr,sizeof(addr));
    if(mlen != len){
        error();
        perror("sendto");
        return -1;
    }
    return 0;
}
int mrecvfrom(int fd,char* buf,int len){
    int mlen;
    mlen = recvfrom(fd,buf,len,0,NULL,NULL);
    if(mlen <=0){
        error();
        return -1;
    }
    return mlen;
}
