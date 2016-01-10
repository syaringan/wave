#ifndef MSOCKET_H
#define MSCOKET_H

int msendto(int fd,char* buf,int len,int port);
int mrecvfrom(int fd,char* buf,int len,int port);
int getsocket(int mport);
#endif
