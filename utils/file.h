#ifndef FILE_H
#define FILE_H
/**
 * 向文件里面插入数据，并且维持原来文件的偏移量
 */
int file_insert(int fd,int offset,unsigned char* buf,int len);
#endif
