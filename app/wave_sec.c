
#include "../utils/list.h"
#include<pthread.h>
#include<stddef.h>
#include"../utils/af_unix.h"

#define SERVICE "/var/tmp/wave_sec.socket"
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


