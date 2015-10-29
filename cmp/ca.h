#ifndef CA_H
#define CA_H

u32 ca_write(int fd,u8* buf,u32 len);
s32 ca_try_read(int fd,u8* buf,u32 len);
//s32 ca_read(u8* buf,u32 len);
#endif
