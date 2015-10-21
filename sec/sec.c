/*************************************************************************
    > File Name: sec.c
    > Author: kyo
    > Email:  604079771@qq.com 
    > Created Time: 2015年10月15日 星期四 17时12分57秒
 ************************************************************************/

#include "./sec.h"
#include "../pssme/pssme.h"
#include "../data/data.h"
#include "../cme/cme.h"
#define INIT(m) memset(&m,0,sizeof(m))
//未测
result sec_signed_wsa(struct sec_db* sdb,string* data,serviceinfo_array* permissions,time32 life_time,string* signed_wsa){
    result ret = SUCCESS;
    struct certificate_chain chain;
    string permission_indices;
    cmh cmh;
    two_d_location td_location;
    tobesigned_wsa tbs_wsa;

    INIT(chain);
    INIT(permission_indices);
    INIT(td_location);
    INIT(tbs_wsa);

    ret = get_current_location(&td_location);
    if(ret != SUCCESS)
        goto fail;

    ret = pssme_cryptomaterial_handle(sdb, permissions, &two_dl, &permission_indices, &cmh, &chain);
    if(ret != SUCCESS)
        goto fail;

    //填充tobesigned_wsa中的permission_indices
    tbs_wsa.permission_indices.len = permission_indices.len;
    tbs_wsa.permission_indices.buf = malloc(sizeof(u8)*permission_indices->len);
    if(tbs_wsa.permission_indices.buf == NULL){
        ret = FAILURE;
        goto fail;
    }
    memcpy(tbs_wsa.permission_indices.buf, permission_indices.buf, permission_indices.len);
    
    //设置use_location和use_generation_time flag
    tbs_wsa.tf = tbs_wsa.tf & USE_GENERATION_TIME & USE_LOCATION;

    //填充data
    tbs_wsa.data.len = data->len;
    tbs_wsa.data.buf = malloc(sizeof(u8)*data->len);
    if(tbs_wsa.data.buf == NULL){
        ret = FAILURE;
        goto fail;
    }
    memcpy(tbs_wsa.data.buf, data->buf, data->len);

    //对generation_time和generation_location编码填充，暂时没有

    tbs_wsa.expiry_time = life_time;
    tbs_wsa.tf = tbs_wsa.tf & EXPIRES;

    //对tobesigned_wsa进行编码，然后签名，填充signed_wsa，暂时没有
    }

fail:
    certificate_chain_free(&chain);
    string_free(&permission_indices);
    two_d_location_free(&td_location);
    tobesigned_wsa_free(&tbs_wsa);
    return ret;
}
