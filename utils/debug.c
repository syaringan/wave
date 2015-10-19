#include "debug.h"
#include <stdarg.h>
#include <stdio.h>
int wave_debug_level = MSG_DEBUG;
void wave_printf(int level,const char *fmt,...){
    va_list ap;

    va_start(ap,fmt);
    if(level > wave_debug_level){
        vprintf(fmt,ap);
        printf("\n");
    }
}
void wave_printf_fl(int level,const char *fmt,...){
    va_list ap;

    va_start(ap,fmt);
    if(level > wave_debug_level){
        vprintf(fmt,ap);
        printf("  %s %d\n",__file__,__line__);
    }
}
void wave_error_printf(const char* fmt,...){
   va_list ap;
    int level = MSG_ERROR;
    va_start(ap,fmt);
    if(level > wave_debug_level){
        vprintf(fmt,ap);
        printf("  %s %d\n",__file__,__line__);
    }
}

