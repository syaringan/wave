#ifndef DEBUG_H
#define DEBUG_H
enum{
  MSG_DEBUG,MSG_INFO,MSG_WARNING,MSG_ERROR  
};

extern int wave_debug_level;
void wave_printf(int level,const char *fmt,...);
#endif
