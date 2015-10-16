/*************************************************************************
    > File Name: sec.c
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2015年10月15日 星期四 17时12分57秒
 ************************************************************************/

#include "./sec.h"
#include "../pssme/pssme.h"
#include "../data/data.h"
#define INIT(m) memset(&m,0,sizeof(m))

result sec_signed_wsa(struct sec_db* sdb,
                string* data,
                serviceinfo_array* permissions,
                time32 life_time,

                string* signed_wsa){
    result ret = SUCCESS;
    struct certificate_chain chain;
    INIT(chain);
    string *permission_indices = string_malloc(permissions->len);
    cmh cmh;    
    two_d_location *two_dl = get_current_location();

    ret = pssme_cryptomaterial_handle(sdb, permissions, two_dl, permission_indices, &cmh, &chain);

    if(ret == SUCCESS){
        tobesigned_wsa tbs_wsa;
        INIT(tbs_wsa);

        tbs_wsa.permission_indices.len = permission_indices->len;
        memcpy(tbs_wsa.permission_indices.buf, permission_indices->buf, permission_indices->len);

        
        
        tbs_wsa.data.len = data->len;
        memcpy(tbs_wsa.data.buf, data->buf, data->len);

        tbs_wsa.expiry_time = life_time;
    }
    return ret;
}
