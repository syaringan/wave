#include"file.h"
#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>
#include<fcntl.h>

int file_insert(int fd,int offset,unsigned char* buf,int len){
    int origin_offset,mfd,mbuf_len = 4096,read_len;
    unsigned char* mbuf =NULL;
    char* name = "./woxiangqigemingzibuchongfu";
    if(buf == NULL || len == 0)
        return -1;
    mbuf = (unsigned char*)malloc(mbuf_len);
    if(mbuf == NULL)
        goto fail;

    origin_offset = lseek(fd,0,SEEK_CUR);
    if(origin_offset == -1){
       printf("获取元文件的原偏移量失败\n");
       goto fail; 
    }
    if ( lseek(fd,offset,SEEK_SET) == -1){
        printf("移动偏移量失败 %s %d\n",__FILE__,__LINE__);
        goto fail;
    }

    mfd = open(name,O_RDWR|O_CREAT);
    if(mfd <0){
        printf("打开零时文件失败\n");
        goto fail;
    }
    do{
        read_len = read(fd,mbuf,mbuf_len);
        if(read_len < 0){
            printf("是否开了读的权利");
            goto fail;
        }
        write(mfd,mbuf,read_len);
    }while(read_len !=0);

    if(lseek(fd,offset,SEEK_SET)  == -1 ||
            write(fd,buf,len) != len){
        printf("写入插入的数据失败");
        goto fail;
    }
   
    if ( lseek(mfd,0,SEEK_SET) == -1){
        goto fail;
    }
    do{
        read_len = read(mfd,mbuf,mbuf_len);
        if(read_len < 0)
            goto fail;
        write(fd,mbuf,read_len);
    }while(read_len !=0);
    free(mbuf);
    remove(name);
    close(mfd);
    lseek(fd,origin_offset,SEEK_SET);
    return 0;
fail:
    if(mbuf != NULL)
        free(mbuf);
    printf("file_insert_error %s %d\n",__FILE__,__LINE__);
    remove(name);
    if(mfd >=0 )
        close(mfd);
    lseek(fd,origin_offset,SEEK_SET);
    return -1;

}
