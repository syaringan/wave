#include "sec/sec_db.h"
/**
 * 当读到文件结束符或者错误的时候 返回错误
 */
int do_client_request(struct sec_db* sdb,int fd);
