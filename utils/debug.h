#ifndef DEBUG_H
#define DEBUG_H
#include<stdio.h>

#define HASHEDID8_FORMAT %x %x %x %x %x %x %x %x
#define HASHEDID8_VALUE(n) n.hashedid8[0],n.hashedid8[1],n.hashedid8[2],n.hashedid8[3],\
                                n.hashedid8[4],n.hashedid8[5],n.hashedid8[6],n.hashedid8[7] 
enum{
  MSG_DEBUG,MSG_INFO,MSG_WARNING,MSG_ERROR  
};

#define DEBUG
#ifdef DEBUG
//extern int wave_debug_level;
void wave_printf(int level,const char *fmt,...);
void wave_printf_fl(int level,const char* fmt,...);
void wave_error_printf(const char*fmt,...);
static inline void wave_malloc_error(){
    printf("内存分配失败  %s %d\n",__FILE__,__LINE__);
}
#else
#define wave_printf(args...) do{}while(0)
#define wave_error_printf(args...) do{}while(0)
#define wave_malloc_error() do{}while(0);
#endif 
#endif
