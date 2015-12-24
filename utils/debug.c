#include "debug.h"
#include <stdarg.h>
#include <stdio.h>

#ifdef DEBUG
static int wave_debug_level = MSG_DEBUG;
static void** ptr=NULL;
void wave_printf(int level,const char *fmt,...){
    va_list ap;

    va_start(ap,fmt);
    if(level >= wave_debug_level){
        vprintf(fmt,ap);
        printf("\n");
    }
}
void wave_printf_fl(int level,const char *fmt,...){
    va_list ap;

    va_start(ap,fmt);
    if(level >= wave_debug_level){
        vprintf(fmt,ap);
        printf("  %s %d\n",__FILE__,__LINE__);
    }
}
void wave_error_printf(const char* fmt,...){
   va_list ap;
    int level = MSG_ERROR;
    va_start(ap,fmt);
    if(level >= wave_debug_level){
        vprintf(fmt,ap);
        printf("\n");
    }
}
void point_save(void **p){
    ptr = p;
}
void point_show(){
    if(ptr != NULL)
        printf("point %p\n",*ptr);
}
#endif
