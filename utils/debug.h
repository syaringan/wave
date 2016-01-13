#ifndef DEBUG_H
#define DEBUG_H
#include<stdio.h>

#define HASHEDID8_FORMAT "%02x %02x %02x %02x %02x %02x %02x %02x"
#define HASHEDID8_VALUE(n) n.hashedid8[0],n.hashedid8[1],n.hashedid8[2],n.hashedid8[3],\
                                n.hashedid8[4],n.hashedid8[5],n.hashedid8[6],n.hashedid8[7] 

#define CERTID10_FORMAT "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x"
#define CERTID10_VALUE(n) n.certid10[0],n.certid10[1],n.certid10[2],n.certid10[3],\
                                n.certid10[4],n.certid10[5],n.certid10[6],n.certid10[7],n.certid10[8],n.certid10[9] 
#define POINT_X_32_FORMAT "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x"
#define POINT_X_32_VALUE(n) n.buf[0],n.buf[1],n.buf[2],n.buf[3],n.buf[4],n.buf[5],n.buf[6],n.buf[7],n.buf[8],n.buf[9],n.buf[10],n.buf[11],n.buf[12],n.buf[13],n.buf[14],n.buf[15],n.buf[16],n.buf[17],n.buf[18],n.buf[19],n.buf[20],n.buf[21],n.buf[22],n.buf[23],n.buf[24],n.buf[25],n.buf[26],n.buf[27],n.buf[28],n.buf[29],n.buf[30],n.buf[31]

#define POINT_X_28_FORMAT "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x"

#define POINT_X_28_VALUE(n) n.buf[0],n.buf[1],n.buf[2],n.buf[3],n.buf[4],n.buf[5],n.buf[6],n.buf[7],n.buf[8],n.buf[9],n.buf[10],n.buf[11],n.buf[12],n.buf[13],n.buf[14],n.buf[15],n.buf[16],n.buf[17],n.buf[18],n.buf[19],n.buf[20],n.buf[21],n.buf[22],n.buf[23],n.buf[24],n.buf[25],n.buf[26],n.buf[27]

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
void point_save(void **p);
void point_show();
#else
#define wave_printf(args...) do{}while(0)
#define wave_error_printf(args...) do{}while(0)
#define wave_malloc_error() do{}while(0);
#endif 
#endif
