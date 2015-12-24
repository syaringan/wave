#include"af_unix.h"
#include<sys/socket.h>
#include<sys/un.h>
#include<errno.h>
#include<stddef.h>
#include<pthread.h>
#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<sys/stat.h>
#define QLEN 10
#define STALE 30 
#define CLI_PATH "./"
#define CLI_PERM S_IRWXU

int serv_listen(const char *name){
    int fd,len,err,rval;
    struct sockaddr_un un;

    if(strlen(name) >= sizeof(un.sun_path)){
        printf("名字过长了 %d %s\n",__LINE__,__FILE__);
        return -1;
    }

    if( (fd = socket(AF_UNIX,SOCK_STREAM,0)) < 0 ){
        printf("申请socket失败 %s %d\n",__FILE__,__LINE__);
        return -1;
    }

    memset(&un,0,sizeof(un));
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path,name);
    len = offsetof(struct sockaddr_un,sun_path) + strlen(name);

    unlink(name);//吧上次遗留下来的删除掉
    if( bind(fd,(struct sockaddr*)&un,len) < 0){
        close(fd);
        printf("bind失败  这里有可能是名字已经存在了%s %d\n",__FILE__,__LINE__);
        return -1;
    }
    
    if( listen(fd,QLEN) < 0){
        perror("listen ");
        printf("listen 失败 %s %s %d\n",strerror(errno),__FILE__,__LINE__);
        close(fd);
        return -1;
    }
    return fd;
}

int serv_accept(int listenfd,uid_t *uidptr){
    int clifd,err,rval;
    socklen_t len;
    time_t staletime;
    struct sockaddr_un un;
    struct stat statbuf;
    char *name;

    if( (name = malloc(sizeof(un.sun_path) + 1)) == NULL){
       printf("malloc fail \n");
       return -1;
    }

    len = sizeof(un);
    while(1){
        if( (clifd = accept(listenfd,(struct sockaddr*)&un,&len)) < 0 ){
            if(errno != EINTR){
                free(name);
                printf("accept 失败\n");
                return -1;
            }
            else
                continue;
        }
        break;
    }
/*
    len -= offsetof(struct sockaddr_un,sun_path);
    memcpy(name,un.sun_path,len);
    name[len] = 0;
    
    printf("%s\n",name);    
    if(stat(name,&statbuf) < 0 ){
        perror("stat:");
        printf("获取文件状态失败%s %d\n",__FILE__,__LINE__);
        close(clifd);
        return -1;
    }

#ifdef S_ISSOCK
    if( S_ISSOCK(statbuf.st_mode) == 0){
        printf("这个文件不是socket文件 %s %d\n",__FILE__,__LINE__);
        close(clifd);
        return -1;
    }
#endif

    if( (statbuf.st_mode & (S_IRWXG | S_IRWXO)) || 
            (statbuf.st_mode & S_IRWXU) != S_IRWXU){
        printf("权限检查有问题 %s %d\n",__FILE__,__LINE__);
        close(clifd);
        return -1;
    }

    staletime =  time(NULL) - STALE;

    if(statbuf.st_atime < staletime || 
            statbuf.st_ctime < staletime || 
            statbuf.st_mtime < staletime ){
        printf("时间早了 %s %d\n",__FILE__,__LINE__);
        close(clifd);
        return -1;
    }

    if(uidptr != NULL){
        *uidptr = statbuf.st_uid;
    }
    unlink(name);
    free(name);
    */
    return clifd;
}

int cli_connect(const char *name){
    int fd,len,err;
    struct sockaddr_un un,sun;
    
    if(strlen(name) >= sizeof(un.sun_path)){
        printf("名字过长了 %s %d\n",__FILE__,__LINE__);
        return -1;
    }

    if((fd = socket(AF_UNIX,SOCK_STREAM,0)) < 0){
        printf("socket 申请失败 %s %d\n",__FILE__,__LINE__);
        return -1;
    }
/*
    memset(&un,0,sizeof(un));
    un.sun_family = AF_UNIX;
    sprintf(un.sun_path,"%s%05ld%05ld",CLI_PATH,(long)getpid(),(long)pthread_self());
    printf("%s\n",un.sun_path); 
    len = offsetof(struct sockaddr_un,sun_path) + strlen(un.sun_path);

    unlink(un.sun_path);
    if(bind(fd,(struct sockaddr*)&un,len) < 0){
        printf("bind fail %s %d\n",__FILE__,__LINE__);
        return -1;
    }
    if(chmod(un.sun_path,CLI_PERM) < 0){
        perror("chmod");
        printf("设置文件的权限错误 %s %d\n",__FILE__,__LINE__);
        close(fd);
        return -1;
    }
*/
    memset(&sun,0,sizeof(sun));
    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path,name);
    len = offsetof(struct sockaddr_un,sun_path) + strlen(name);
    if(connect(fd,(struct sockaddr*)&sun,len) < 0){
        printf("connect fail  %s %d\n",__FILE__,__LINE__);
        close(fd);
        return -1;
    }
    return fd;
}

