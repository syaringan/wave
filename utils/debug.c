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
