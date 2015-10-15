/*************************************************************************
    > File Name: sec.c
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2015年10月15日 星期四 17时12分57秒
 ************************************************************************/

#include "./sec.h"
#define INIT(m) memset(&m,0,sizeof(m))

result sec_signed_wsa(struct sec_db* sdb,
                string* data,
                serviceinfo_array* permissions,
                time32 life_time,

                string* signed_wsa){
    result ret = SUCCESS;
    struct certificate_chain chain;
    int *permission_indices = (int *)malloc(sizeof(int)*permissions->len);
    memset(permission_indices, 0, sizeof(permissions->len));
    INIT(chain);
}
